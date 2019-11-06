package com.example.victolee.springsecurity_login.domain.repository;



import com.example.victolee.springsecurity_login.domain.entity.MemberEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

////Email을 Where 조건절로 하여, 데이터를 가져올 수 있도록 findByEmail() 메서드를 정의했습니다.
public interface MemberRepository extends JpaRepository<MemberEntity, Long> {
    Optional<MemberEntity> findByEmail(String userEmail);
}
