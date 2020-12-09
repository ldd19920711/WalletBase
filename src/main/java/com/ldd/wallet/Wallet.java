package com.ldd.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import com.ldd.foundation.utils.MetaUtil;
import com.ldd.foundation.utils.NumericUtil;
import com.ldd.wallet.keystore.EncMnemonicKeystore;
import com.ldd.wallet.keystore.ExportableKeystore;
import com.ldd.wallet.keystore.HDMnemonicKeystore;
import com.ldd.wallet.keystore.IMTKeystore;
import com.ldd.wallet.keystore.V3Ignore;
import com.ldd.wallet.keystore.V3Keystore;
import com.ldd.wallet.keystore.V3MnemonicKeystore;
import com.ldd.wallet.model.Messages;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.MnemonicAndPath;
import com.ldd.wallet.model.TokenException;


public class Wallet {

  private IMTKeystore keystore;

  public IMTKeystore getKeystore() {
    return keystore;
  }

  public Wallet(IMTKeystore keystore) {
    this.keystore = keystore;
  }

  public String getId() {
    return this.keystore.getId();
  }

  public String getAddress() {
    return this.keystore.getAddress();
  }

  public Metadata getMetadata() {
    return keystore.getMetadata();
  }

  public String getEncXPub() {
    if (keystore instanceof HDMnemonicKeystore) {
      return ((HDMnemonicKeystore) keystore).getEncryptXPub();
    }
    return null;
  }

  public byte[] decryptMainKey(String password) {
    return keystore.decryptCiphertext(password);
  }

  MnemonicAndPath exportMnemonic(String password) {
    if (keystore instanceof EncMnemonicKeystore) {
      EncMnemonicKeystore encMnemonicKeystore = (EncMnemonicKeystore) keystore;
      String mnemonic = encMnemonicKeystore.decryptMnemonic(password);
      String path = encMnemonicKeystore.getMnemonicPath();
      return new MnemonicAndPath(mnemonic, path);
    }
    return null;
  }

  String exportKeystore(String password) {
    if (keystore instanceof ExportableKeystore) {
      if (!keystore.verifyPassword(password)) {
        throw new TokenException(Messages.WALLET_INVALID_PASSWORD);
      }

      try {
        ObjectMapper mapper = new ObjectMapper();
        mapper.addMixIn(IMTKeystore.class, V3Ignore.class);
        return mapper.writeValueAsString(keystore);
      } catch (Exception ex) {
        throw new TokenException(Messages.WALLET_INVALID, ex);
      }
    } else {
      throw new TokenException(Messages.CAN_NOT_EXPORT_MNEMONIC);
    }
  }

  public String exportPrivateKey(String password) {
    if (keystore instanceof V3Keystore || keystore instanceof V3MnemonicKeystore) {
      byte[] decrypted = keystore.decryptCiphertext(password);
      if (keystore.getMetadata().getSource().equals(Metadata.FROM_WIF)) {
        return new String(decrypted);
      } else {
        return NumericUtil.bytesToHex(decrypted);
      }
    } else if (keystore instanceof HDMnemonicKeystore) {
      String xprv = new String(decryptMainKey(password), StandardCharsets.UTF_8);
      DeterministicKey xprvKey = DeterministicKey
          .deserializeB58(xprv, MetaUtil.getNetWork(keystore.getMetadata()));
      DeterministicKey accountKey = HDKeyDerivation
          .deriveChildKey(xprvKey, new ChildNumber(0, false));
      DeterministicKey externalChangeKey = HDKeyDerivation
          .deriveChildKey(accountKey, new ChildNumber(0, false));
      return NumericUtil.bigIntegerToHex(externalChangeKey.getPrivKey());
    }
    throw new TokenException(Messages.ILLEGAL_OPERATION);
  }

  public String exportPrivateKey(String password, int childNumber) {
    if (keystore instanceof V3Keystore || keystore instanceof V3MnemonicKeystore) {
      byte[] decrypted = keystore.decryptCiphertext(password);
      if (keystore.getMetadata().getSource().equals(Metadata.FROM_WIF)) {
        return new String(decrypted);
      } else {
        return NumericUtil.bytesToHex(decrypted);
      }
    } else if (keystore instanceof HDMnemonicKeystore) {
      String xprv = new String(decryptMainKey(password), StandardCharsets.UTF_8);
      DeterministicKey xprvKey = DeterministicKey
          .deserializeB58(xprv, MetaUtil.getNetWork(keystore.getMetadata()));
      DeterministicKey accountKey = HDKeyDerivation
          .deriveChildKey(xprvKey, new ChildNumber(0, false));
      DeterministicKey externalChangeKey = HDKeyDerivation
          .deriveChildKey(accountKey, new ChildNumber(childNumber, false));
      return NumericUtil.bigIntegerToHex(externalChangeKey.getPrivKey());
    }
    throw new TokenException(Messages.ILLEGAL_OPERATION);
  }

  public String exportPrivateKey(String password, int childNumber,boolean isChange) {
    if (keystore instanceof V3Keystore || keystore instanceof V3MnemonicKeystore) {
      byte[] decrypted = keystore.decryptCiphertext(password);
      if (keystore.getMetadata().getSource().equals(Metadata.FROM_WIF)) {
        return new String(decrypted);
      } else {
        return NumericUtil.bytesToHex(decrypted);
      }
    } else if (keystore instanceof HDMnemonicKeystore) {
      String xprv = new String(decryptMainKey(password), StandardCharsets.UTF_8);
      DeterministicKey xprvKey = DeterministicKey
          .deserializeB58(xprv, MetaUtil.getNetWork(keystore.getMetadata()));
      DeterministicKey changeKey ;
      if (isChange) {
        changeKey = HDKeyDerivation.deriveChildKey(xprvKey, ChildNumber.ONE);
      }else {
        changeKey = HDKeyDerivation.deriveChildKey(xprvKey, ChildNumber.ZERO);
      }
      DeterministicKey externalChangeKey = HDKeyDerivation.deriveChildKey(changeKey, new ChildNumber(childNumber));
      return NumericUtil.bigIntegerToHex(externalChangeKey.getPrivKey());
    }
    throw new TokenException(Messages.ILLEGAL_OPERATION);
  }

  boolean verifyPassword(String password) {
    return keystore.verifyPassword(password);
  }

  public String newReceiveAddress(int nextRecvIdx) {
    if (keystore instanceof HDMnemonicKeystore) {
      return ((HDMnemonicKeystore) keystore).newReceiveAddress(nextRecvIdx);
    } else {
      return keystore.getAddress();
    }
  }

  public String newReceiveAddress(int nextRecvIdx, boolean isChange) {
    if (keystore instanceof HDMnemonicKeystore) {
      return ((HDMnemonicKeystore) keystore).newReceiveAddress(nextRecvIdx, isChange);
    } else {
      return keystore.getAddress();
    }
  }

  public long getCreatedAt() {
    return this.keystore.getMetadata().getTimestamp();
  }

  boolean hasMnemonic() {
    return this.keystore instanceof EncMnemonicKeystore;
  }


  boolean delete(String password) {
    return keystore.verifyPassword(password) && WalletManager.generateWalletFile(keystore.getId())
        .delete();
  }

}
