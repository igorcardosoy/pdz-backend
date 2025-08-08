package br.app.pdz.api.repository;

import br.app.pdz.api.model.MineAccount;
import br.app.pdz.api.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MineAccountRepository extends JpaRepository<MineAccount, Long> {

   MineAccount getMineAccountsByEmail(String email);
}
