package br.app.pdz.api.controller;


import br.app.pdz.api.dto.MineAccountRequest;
import br.app.pdz.api.dto.MineEmailRequest;
import br.app.pdz.api.dto.MineCodeDTO;
import br.app.pdz.api.service.MineCodeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RestController
@RequestMapping("/pdz-api/mine-codes")
public class MineCodeController {

    private final MineCodeService mineCodeService;

    public MineCodeController(MineCodeService mineCodeService) {
        this.mineCodeService = mineCodeService;
    }

    @GetMapping("/code-2AF")
    public ResponseEntity<MineCodeDTO> get2AFCode(@RequestBody MineEmailRequest mineEmailRequest) throws IOException {
        MineCodeDTO code = mineCodeService.get2AFCode(mineEmailRequest);

        return ResponseEntity.ok(code);

    }

    @PostMapping("/create_account")
    public ResponseEntity<String> createAccount(@RequestBody MineAccountRequest mineAccountRequest) throws IOException {
        mineCodeService.createMineAccount(mineAccountRequest);
        return ResponseEntity.ok("Account created successfully");
    }
}
