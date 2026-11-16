# 导出目录解析的可信证据边界分析

**对象**：`pefile.py` 中 `PE.parse_export_directory`（pefile.py:5424-5683）及其辅助函数
**方法**：源码审查 + 本地生成的最小 PE 样本（受控矛盾注入）复现
**日期**：2026-11-16

---

## 1. 问题框架

导出目录解析需要在三类互相可能矛盾的证据之间建立解释顺序：

1. **序号基数（Base）** —— `IMAGE_EXPORT_DIRECTORY.Base`，决定导出序号的起始值；
2. **函数/名称计数（NumberOfFunctions / NumberOfNames）** —— 决定三张表（EAT、ENT、EOT）的读取长度；
3. **字符串 RVA（转发字符串与名称字符串）** —— 决定一个导出地址应被解释为"代码地址"还是"转发字符串指针"，以及名称从何而来。

当这些证据矛盾时（计数大于实际表、序号越界、RVA 落在声明目录尺寸之外等），解析器实际遵循的优先级是什么？哪些证据被当作"可信"，哪些被静默丢弃或误解释？以下先给源码证据，再给可复现观察，最后列出验证缺口与修正方案。

## 2. 源码证据：解析器实际的解释顺序

通读 `parse_export_directory` 后，实际优先级（从高到低）为：

### 2.1 文件物理边界是最终仲裁者

三张表的读取长度都被 `length_until_eof`（pefile.py:5454-5455，即"文件剩余字节数"）钳制：

```python
address_of_functions = self.get_data(
    export_dir.AddressOfFunctions,
    min(length_until_eof(export_dir.AddressOfFunctions),
        export_dir.NumberOfFunctions * 4))   # pefile.py:5472-5478
```

循环次数再被 `safety_boundary`（pefile.py:5489-5497, 5606-5614）钳制：若表 RVA 落在某节内，上界为该节剩余字节；否则上界为整个文件长度。**声明的 NumberOfFunctions/NumberOfNames 从不被信任为真实表长**，只作为上限之一参与 `min()`。

### 2.2 序号表对函数表的索引：一次越界即整体放弃

第一阶段（按名称）循环中（pefile.py:5501-5513）：

```python
symbol_ordinal = self.get_word_from_data(address_of_name_ordinals, i)
if symbol_ordinal is not None and symbol_ordinal * 4 < len(address_of_functions):
    symbol_address = self.get_dword_from_data(address_of_functions, symbol_ordinal)
else:
    # Corrupt? a bad pointer... we assume it's all useless, no exports
    return None
```

注意 `len(address_of_functions)` 是**经 EOF 钳制后的实际字节数**，而非 `NumberOfFunctions * 4`。因此"序号越界"的判定混合了两个不同来源的矛盾：序号表与函数计数矛盾、或文件被截断——两者都导致 `return None`，**丢弃包括已解析条目在内的全部导出**，且不产生任何警告。

### 2.3 转发判定：仅由声明的目录区间 `[rva, rva+size)` 仲裁

pefile.py:5520 与 5635-5638：

```python
if rva <= symbol_address < rva + size:
    forwarder_str = self.get_string_at_rva(symbol_address)
```

`size` 来自数据目录（DataDirectory[0].Size），是**声明值**。转发字符串本身不做任何字符集校验（对比名称字符串要过 `is_valid_function_name`，pefile.py:5542）。区间判定先于一切其他语义检查，是"地址 vs 字符串"解释分歧的唯一仲裁者。

### 2.4 名称字符串：字符集校验，失败则中断但保留部分结果

pefile.py:5539-5544：名称过 `is_valid_function_name(..., relax_allowed_characters=True)`，失败则 `break`（保留已收集条目，追加警告）。与 2.2 的 `return None` 形成明显不对称。

### 2.5 Base 从不被校验

`export_dir.Base` 只用于 `ordinal = Base + index`（pefile.py:5581, 5663, 5619）。Base=0、Base=0x80000000 均被静默接受。Base 与序号表内容是否一致（例如序号表是否覆盖 `[0, NumberOfFunctions)` 的全部区间）从不检查。

### 2.6 第二阶段（纯序号）循环的额外不对称

pefile.py:5618-5675：

- 循环结束后若 `export_parsing_loop_completed_normally` 为假则 `return None`（pefile.py:5670-5675）——**丢弃第一阶段已成功解析的全部命名导出**；
- `get_dword_from_data` 越界返回 `None`（pefile.py:7283-7284）时，失败预算减 1，但若预算未耗尽，控制流**继续下落**：`symbol_address == 0` 对 `None` 不成立，于是 `None` 被计入 `symbol_counts` 并以 `address=None` 追加为一条导出（pefile.py:5661-5668）。

### 2.7 RVA→文件偏移的回退路径

`get_string_at_rva`（pefile.py:6477-6486）与 `get_data`（pefile.py:6409-6423）、`get_offset_from_rva`（pefile.py:6457-6475）在 RVA 不属于任何节时，**把 RVA 当作文件偏移直接切片**（`self.__data__[rva:...]`）。在节的 VirtualAddress ≠ PointerToRawData 的正常 PE 中，这条回退会把不可信的 RVA 静默重解释到错误的物理位置。

## 3. 可复现观察（最小 PE 实验）

实验方法：用参数化生成器构造单 `.edata` + `.text` 两节的最小 PE32（生成器与样本位于仓库外 `/tmp/exp_analysis/`，解析时以 `python3 -I` 运行），逐项注入矛盾。以下为观察结果（A–M 与样本一一对应）：

| 实验 | 注入的矛盾 | 观察到的行为 |
|---|---|---|
| A | 无（基线：3 函数 2 名称，1 条转发） | 正确：代码地址 `forwarder=None`，转发条目 `forwarder=b'OTHERDLL.Target'` |
| B | 名称序号=5 ≥ NumberOfFunctions=2 | **整个 `DIRECTORY_ENTRY_EXPORT` 消失**，无任何导出相关警告（对应 2.2） |
| C | 文件在函数表第 3 项前截断 | 第一阶段循环因 `safety_boundary` 为负而**静默零迭代**（无警告）；第二阶段输出 2 条 `name=None` 的序号导出。截断同时吃掉了名称表，但解析器未报告名称证据丢失 |
| D | 转发字符串在声明 `dir_size` 之外 | 转发被误分类为代码地址：`forwarder=None`，`address=0x1200`（字符串 RVA 被当作函数地址） |
| E | `dir_size=0x100000` 覆盖整个映像 | 真实代码 RVA 被误分类为转发：`forwarder=b''`（读到零填充）；其中一项因 RVA 恰好不可映射到文件偏移，**命名导出被 `continue` 静默丢弃**（pefile.py:5522-5525），名称永久丢失 |
| F | 名称含 `\xff` | 保留已解析条目后中断，追加 `AddressOfNames ... invalid address` 警告（警告文案与实际原因——名称字符非法——不符） |
| G | 函数表声明 10 项、文件仅剩 4 项可读 | **追加 6 条 `address=None` 的幻影导出**（对应 2.6 的下落缺陷） |
| H | Base=0 / Base=5 | 序号分别整体平移为 0 起始 / 5 起始，无任何一致性检查（对应 2.5） |
| I | 名称 RVA=0x300 不属于任何节 | 名称被读为 `b'DECOY_at_file_offset_0x300'`——RVA 被当作文件偏移，读到了攻击者可在该偏移种植的内容（对应 2.7） |
| J | 转发目标为 `\x01\x02\xff\xfe` | 原样接受为 `forwarder`，无字符校验（对比 F 中名称被拒） |
| K | 转发 RVA 在膨胀的 dir_size 内但不可映射 | 命名导出被 `continue` 丢弃；第二阶段又以 `name=None, forwarder=b''` 重新登记同一序号——**同一条目名称丢失且凭空多出空转发** |
| L | NumberOfNames=0x4000，实际表 1 项 | 序号表越界读入字符串区，触发 2.2 的 `return None`：**全部导出消失** |
| M | NumberOfFunctions=0x8000，实际表 1 项 | 第二阶段把相邻的名称表、字符串区当作函数地址解析，产生 6 条幻影导出；其中一条的"地址"恰为名称字符串的 RVA，被解释为 `forwarder=b'FuncA'`——**名称字符串被同时当作名称和转发字符串消费** |

### 由观察得出的实际解释顺序

当 Base、函数计数、字符串 RVA 三方矛盾时，解析器的实际行为顺序是：

1. **文件 EOF 与节边界**（物理证据）先于一切声明值；
2. **声明的目录区间 `[rva, rva+size)`** 先于地址语义——它单方面决定一个 DWORD 是"代码地址"还是"字符串指针"，且字符串内容不校验（D、E、J）；
3. **序号表对（EOF 钳制后的）函数表的索引**是一票否决项——越界即全灭（B、L），而计数虚高本身不否决（M 继续解析并产生幻影）；
4. **Base** 无任何仲裁力，纯粹透传（H）；
5. 名称字符集是**唯一的内容级校验**，且只作用于名称，不作用于转发字符串（F vs J）。

## 4. 可信与不可信证据的分界

综合源码与实验，当前实现的分界线如下：

**被当作可信的（实际未必可信）：**
- 数据目录声明的 `Size` —— 单独决定转发/代码解释（实验 D、E 证明其可被畸形文件任意操纵）；
- 落在 `[rva, rva+size)` 内的字节流 —— 作为转发字符串不经校验直接采纳（J）；
- 不属于任何节的 RVA —— 经 2.7 回退被当作文件偏移，指向的内容被当作名称/转发字符串（I）；
- EOF 钳制后函数表"之外"的相邻数据 —— 计数虚高时被当作函数地址（M）。

**被当作不可信的（处理过激或不一致）：**
- 单个越界序号 —— 导致全部导出被丢弃（B、L），而非仅丢弃该条目；
- 单个非法名称字符 —— 中断名称循环（合理），但同样程度的垃圾在转发字符串中却被接受（J 的不对称）；
- 第二阶段循环异常 —— 连带丢弃第一阶段已验证的命名导出（2.6）。

## 5. 验证缺口（源码证据 vs 可复现观察）

以下为**仅有源码证据、本次未能复现或无法复现**的论断，列为开放缺口：

1. **pefile.py:5545-5559 的重试块是死代码**：`get_offset_from_rva(symbol_name_address)` 是纯函数，首次抛 `PEFormatError` 后，except 分支内对同一 RVA 的原样重试必然再次失败。效果只是失败预算被双倍扣减。无法构造"首次失败、重试成功"的样本，故该分支的真实意图无法从行为验证。
2. **`symbol_name_address is None` 时的失败预算（pefile.py:5532-5537）形同虚设**：预算扣减后控制流下落到 `get_string_at_rva(None)` 返回 `None`，`is_valid_function_name(None)` 为假即 `break`——第一条 `None` 名称地址就终止循环，预算从未真正起作用。源码可推，未单独构造样本。
3. **pefile.py:5582-5588 的 `ordinal_offset`/`address_offset` 可能抛出未捕获的 `PEFormatError`**：若表项在第一阶段循环期间可读、但 `get_offset_from_rva` 失败，异常会逃出 `parse_export_directory`。调用方 `parse_data_directories` 在常规路径捕获 `PEFormatError`（pefile.py:3817-3822），但 `forwarded_exports_only=True` 路径（pefile.py:3804-3808）**没有** try/except，异常会传播给库使用者。未构造触发样本（需要表数据可读而偏移映射失败的精细布局）。
4. **实验 C 中"负 safety_boundary 导致零迭代"的机制**是由输出（无名称导出、无警告）反推 + 源码计算确认的，未在调试器中单步验证。
5. 实验均基于 PE32/单导出节布局；PE32+ 与多节重叠布局未覆盖。

## 6. 修正方案

按"统一信任层级、失败局部化、校验对称"三原则，建议（按优先级）：

### 6.1 失败局部化：取消一票否决

- **2.2 的 `return None`（pefile.py:5511-5513）改为 `continue` 并消耗失败预算**：单个越界序号只丢弃该条目，与名称循环其余失败路径一致。B、L 类样本将保留合法导出。
- **第二阶段末尾的 `return None`（pefile.py:5670-5675）改为保留 `exports` 并仅追加警告**：第一阶段已验证的命名导出不应被第二阶段的失败株连。
- **G 类幻影**：`symbol_address is None` 时在预算扣减后 `continue`，禁止 `None` 下落到 `exports.append`（pefile.py:5625-5668）。

### 6.2 转发判定增加交叉证据，而非单看声明区间

声明的 `Size` 不可信（D、E）。建议按顺序仲裁：

1. RVA 在 `[rva, rva+size)` 内 **且** 该处可映射到文件偏移 **且** 读到的字节构成合法转发语法（`DLL.Name`，可复用 `is_valid_function_name` 的字符集并允许 `.`，且非空）→ 判定为转发；
2. RVA 指向可执行节 → 判定为代码地址（即使落在声明区间内，E 类误分类可纠正）；
3. 两者皆不满足 → 保留地址原值、`forwarder=None`，并追加警告，而不是 `continue` 丢弃整个命名条目（修 K/E 的名称丢失：pefile.py:5522-5525 的 `continue` 应改为 `forwarder_str=None` 后继续登记）。

### 6.3 校验对称化

- 转发字符串与名称字符串应用同一字符集校验（修 J 的不对称）；空转发字符串视为无效（E、K 中的 `forwarder=b''`）。
- 名称/转发字符串 RVA 不属于任何节时，**禁用 2.7 的 RVA==偏移回退**或至少追加警告（修 I：该回退对导出字符串是静默的错误位置读取；可限定仅在文件无节或 RVA < SizeOfHeaders 时启用）。

### 6.4 计数与 Base 的一致性检查（仅警告，不改变解析结果）

- `NumberOfFunctions < max(序号表)+1` 或 `NumberOfNames > NumberOfFunctions` 时追加警告（M、L 的计数矛盾目前完全无声）；
- `Base == 0` 或序号表未覆盖 `[0, NumberOfFunctions)` 时追加警告（H）；
- 第二阶段循环上限应同时受 `len(address_of_functions)/4`（EOF 钳制后的实际表长）约束，避免把相邻数据当函数地址（修 M 的幻影导出）。

### 6.5 死代码与预算语义清理

- 删除 pefile.py:5552-5559 的不可能重试块（验证缺口 1）；
- 修 `symbol_name_address is None` 时下落导致的预算失效（验证缺口 2）：扣减预算后应 `continue`；
- 给 `forwarded_exports_only=True` 调用路径补上与其他目录一致的 `PEFormatError` 捕获（验证缺口 3，pefile.py:3804-3808）。

### 6.6 测试建议

将本次实验样本固化为回归测试（生成器 60 行，样本各 <2KB，可内联 hex，与 `tests/export_test.py` 现有风格一致）：至少覆盖 B（越界序号保留合法导出）、G（无 `address=None` 条目）、K（命名导出不因转发 RVA 不可映射而丢失）、M（计数虚高不产生幻影导出）四个用例。

---

## 附录：复现方法

```bash
# 生成器与实验脚本位于 /tmp/exp_analysis/{gen.py,run.py}（非仓库文件）
cd /tmp/exp_analysis && python3 -I run.py
```

生成器构造 PE32：DOS 头 + PE 头 + `.edata`（RVA 0x1000）+ `.text`（RVA 0x2000）两节；导出目录的 Base、NumberOfFunctions、NumberOfNames、三表 RVA、声明 dir_size、文件截断点均可参数化，从而精确注入第 3 节各实验的矛盾。解析使用仓库根目录的 `pefile.py`（分支 task/99，HEAD=43ca73f）。
