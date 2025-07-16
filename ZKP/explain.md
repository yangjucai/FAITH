### 代码解释

`main.rs`中验证的是：
$$f = f_1 \cdot f_2^{-1} \quad \text{且} \quad \text{final\_exp}(f) = f^e$$
而`reEncrypt`中使用到的`pairing`验证的是：
$$e(P, Q) = f_{P, Q}^e \quad \text{其中} \quad f_{P, Q} \quad \text{是通过 Miller Loop 迭代构造的}$$

对于`main.rs`中的例子：
- 给定`P(12345, 67890)`和`Q(11111, 22222, 33333)`
- 验证 $e(P, Q)$ 是否满足 $f^{(p^{12} - 1)/r} = 1$


（在`/src/internal/mod.rs`文件里）

### reEncrypt函数操作

- 验证
  - 验证密文签名：调用`verify_signed_value(signed_encrypted_value, ed25519)`
  - 验证重加密密钥签名：调用`verify_signed_value(signed_reencryption_key, ed25519)`
- 模式匹配解包`EncryptedValue`和`ReencryptionKey`（包含`paring`）
  - 对`EncryptedOnce`情况执行第一次重加密：调用`reencrypt_encrypted_once(...)`
  - 对`Reencrypted`情况执行再次重加密：调用`reencrypt_reencrypted_value(...)`
- 将重加密结果重新封装为`EncryptedValue::Reencrypted`
- 对新密文进行签名：调用`sign_value(...)`
- 返回签名后的新密文（封装为`SignedValue<EncryptedValue<FP>>`）
- 若任一签名验证失败，返回错误类型（`InvalidEncryptedMessageSignature`或`CorruptReencryptionKey`）


| 步骤 | 操作                                                                              | 说明                                     |
| ---- | --------------------------------------------------------------------------------- | -------------------------------------- |
| 1    | 验证密文签名（`verify_signed_value(signed_encrypted_value)`）                      | 证明“我看过有效签名，但不泄露签名内容”                   |
| 2    | 验证重加密密钥签名（`verify_signed_value(signed_reencryption_key)`）                | 同上，保护密钥签名隐私                            |
| 3    | 解包（匹配 `EncryptedOnce` / `Reencrypted`）                                       | 属于函数流程控制                       |
| 4    | 重加密：调用 `reencrypt_encrypted_once(...)` 或 `reencrypt_reencrypted_value(...)` | 证明正确地进行了重加密变换 |
| 5    | 重新封装为 `EncryptedValue::Reencrypted`                                           | 只是包装数据结构，不涉及隐私计算                       |
| 6    | 对新密文签名：`sign_value(...)`                                                    | 证明签过，不暴露签名，思路与前面基本一致                   |
| 7    | 返回新的签名密文                                                                   | 外部执行，不需要证明                             |
| 8    | 验签失败时返回错误                                                                  | 错误路径不需电路处理                             |
