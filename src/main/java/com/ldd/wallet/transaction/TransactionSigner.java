package com.ldd.wallet.transaction;

import com.ldd.wallet.Wallet;

public interface TransactionSigner {
  TxSignResult signTransaction(String chainId, String password, Wallet wallet);
}
