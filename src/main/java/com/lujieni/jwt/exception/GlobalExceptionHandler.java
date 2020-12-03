package com.lujieni.jwt.exception;

import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(Exception.class)
    public JSONObject handleException(Exception e){
        log.error("全局异常",e);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("error",e.getMessage());
        return jsonObject;
    }
}
