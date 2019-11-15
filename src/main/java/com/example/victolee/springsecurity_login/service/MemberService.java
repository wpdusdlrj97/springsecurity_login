package com.example.victolee.springsecurity_login.service;

import com.example.victolee.springsecurity_login.domain.Role;
import com.example.victolee.springsecurity_login.domain.entity.MemberEntity;
import com.example.victolee.springsecurity_login.domain.repository.MemberRepository;
import com.example.victolee.springsecurity_login.dto.MemberDto;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class MemberService implements UserDetailsService {

    private MemberRepository memberRepository;

    @Transactional
    public Long joinUser(MemberDto memberDto) { //회원가입을 처리하는 메서드이며, 비밀번호를 암호화하여 저장합니다.
        // 비밀번호 암호화
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        memberDto.setPassword(passwordEncoder.encode(memberDto.getPassword()));

        //save()
        //JpaRepository에 정의된 메서드로, DB에 INSERT, UPDATE를 담당합니다.
        //매개변수로는 Entity를 전달합니다.
        return memberRepository.save(memberDto.toEntity()).getId();
    }

    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        //상세 정보를 조회하는 메서드이며, 사용자의 계정정보와 권한을 갖는 UserDetails 인터페이스를 반환해야 합니다.
        //매개변수는 로그인 시 입력한 아이디인데, 엔티티의 PK를 뜻하는게 아니고 유저를 식별할 수 있는 어떤 값을 의미합니다. Spring Security에서는 username라는 이름으로 사용합니다.
        //예제에서는 아이디가 이메일이며, 로그인을 하는 form에서 name="username"으로 요청해야 합니다.

        Optional<MemberEntity> userEntityWrapper = memberRepository.findByEmail(userEmail);
        MemberEntity userEntity = userEntityWrapper.get();

        List<GrantedAuthority> authorities = new ArrayList<>();

        //롤을 부여하는 코드입니다. 롤 부여 방식에는 여러가지가 있겠지만, 회원가입할 때 Role을 정할 수 있도록 Role Entity를 만들어서 매핑해주는 것이 좋은 방법인것 같습니다. ( 참고 )
        //예제에서는 복잡성을 줄이기 위해, 아이디가 "admin@example.com"일 경우에 ADMIN 롤을 부여했습니다.
        if (("admin@example.com").equals(userEmail)) {
            authorities.add(new SimpleGrantedAuthority(Role.ADMIN.getValue()));
        } else {
            authorities.add(new SimpleGrantedAuthority(Role.MEMBER.getValue()));
        }

        //return은 SpringSecurity에서 제공하는 UserDetails를 구현한 User를 반환합니다. ( org.springframework.security.core.userdetails.User )
        //생성자의 각 매개변수는 순서대로 아이디, 비밀번호, 권한리스트입니다.
        return new User(userEntity.getEmail(), userEntity.getPassword(), authorities);

    }
}
