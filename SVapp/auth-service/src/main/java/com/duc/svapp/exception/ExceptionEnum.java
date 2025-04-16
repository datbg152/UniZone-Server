package com.duc.svapp.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ExceptionEnum {
    INVALID_TOKEN("유효하지 않은 토큰입니다."),
    TIMEOUT_TOKEN("토큰이 만료되었습니다."),
    TOKEN_DOES_NOT_EXIST("토큰이 존재하지 않습니다."),
    INVALID_TOKEN_INFO("토큰 정보가 유효하지 않습니다.");

    private final String message;
}
