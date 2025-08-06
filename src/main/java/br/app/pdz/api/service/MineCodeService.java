package br.app.pdz.api.service;

import br.app.pdz.api.dto.MineAccountRequest;
import br.app.pdz.api.dto.MineEmailRequest;
import br.app.pdz.api.dto.MineCodeDTO;
import br.app.pdz.api.model.MineAccount;
import br.app.pdz.api.repository.MineAccountRepository;
import com.bastiaanjansen.otp.HMACAlgorithm;
import com.bastiaanjansen.otp.TOTPGenerator;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class MineCodeService {

    private final MineAccountRepository mineAccountRepository;

    public MineCodeService(MineAccountRepository mineAccountRepository) {
        this.mineAccountRepository = mineAccountRepository;
    }

    public void createMineAccount(MineAccountRequest mineAccountRequest) {
        if(mineAccountRequest == null ||
           mineAccountRequest.email() == null ||
           mineAccountRequest.secretKey() == null) {
            throw new IllegalArgumentException("Invalid account request");
        }

        MineAccount newAccount = new MineAccount();
        newAccount.setEmail(mineAccountRequest.email());
        newAccount.setSecretKey(mineAccountRequest.secretKey());

        this.mineAccountRepository.save(newAccount);

    }

    public MineCodeDTO get2AFCode(MineEmailRequest mineAccountRequest) {
        MineAccount account = this.mineAccountRepository.getMineAccountsByEmail(mineAccountRequest.email());
        if (account == null) {
            throw new IllegalArgumentException("Account not found");
        }

        try {
            TOTPGenerator totp = new TOTPGenerator.Builder(account.getSecretKey())
                    .withHOTPGenerator(builder -> {
                        builder.withPasswordLength(6);
                    })
                    .withPeriod(Duration.ofSeconds(30))
                    .build();
            return new MineCodeDTO(totp.now());
        } catch (Exception e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }
}
