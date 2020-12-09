package com.ldd.foundation.utils;

import com.google.common.base.Joiner;
import java.util.List;
import org.bitcoinj.crypto.MnemonicCode;
import com.ldd.wallet.model.Messages;
import com.ldd.wallet.model.TokenException;

public class MnemonicUtil {
  public static void validateMnemonics(List<String> mnemonicCodes) {
    try {
      MnemonicCode.INSTANCE.check(mnemonicCodes);
    } catch (org.bitcoinj.crypto.MnemonicException.MnemonicLengthException e) {
      throw new TokenException(Messages.MNEMONIC_INVALID_LENGTH);
    } catch (org.bitcoinj.crypto.MnemonicException.MnemonicWordException e) {
      throw new TokenException(Messages.MNEMONIC_BAD_WORD);
    } catch (Exception e) {
      throw new TokenException(Messages.MNEMONIC_CHECKSUM);
    }
  }

  public static List<String> randomMnemonicCodes() {
    return toMnemonicCodes(NumericUtil.generateRandomBytes(16));
  }

  public static String randomMnemonicStr() {
    List<String> mnemonicCodes=randomMnemonicCodes();
    return Joiner.on(" ").join(mnemonicCodes);
  }


  public static List<String> toMnemonicCodes(byte[] entropy) {
    try {
      return MnemonicCode.INSTANCE.toMnemonic(entropy);
    } catch (org.bitcoinj.crypto.MnemonicException.MnemonicLengthException e) {
      throw new TokenException(Messages.MNEMONIC_INVALID_LENGTH);
    } catch (Exception e) {
      throw new TokenException(Messages.MNEMONIC_CHECKSUM);
    }
  }

}
