package com.example.victolee.springsecurity_login.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;

//Service에서 사용하는 Enum객체입니다.
@AllArgsConstructor
@Getter
public enum Role {
    ADMIN("ROLE_ADMIN"),
    MEMBER("ROLE_MEMBER");

    private String value;
}
