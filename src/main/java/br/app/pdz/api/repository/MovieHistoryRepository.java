package br.app.pdz.api.repository;

import br.app.pdz.api.model.MovieHistory;
import br.app.pdz.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MovieHistoryRepository extends JpaRepository<MovieHistory, Long> {
    List<MovieHistory> findByUserOrderByDownloadedAtDesc(User user);
}

