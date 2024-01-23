package spring.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.jwt.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
