package com.lujieni.jwt.controller;

import com.alibaba.fastjson.JSONObject;

import com.lujieni.jwt.annotation.UserLoginToken;
import com.lujieni.jwt.dao.UserRepository;
import com.lujieni.jwt.entity.User;
import com.lujieni.jwt.service.TokenManager;
import com.lujieni.jwt.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@RequestMapping("api")
@RestController
public class UserApi {
    @Autowired
    UserRepository userRepository;
    @Autowired
    private TokenManager tokenManager;
    //登录
    @PostMapping("/login")
    public Object login(@RequestBody User user){
        JSONObject jsonObject = new JSONObject();
        User userForBase = userRepository.findByUsername(user.getUsername());
        if(userForBase==null){
            jsonObject.put("message","登录失败,用户不存在");
            return jsonObject;
        }else {
            if (!Objects.equals(userForBase.getPassword(),user.getPassword())){
                jsonObject.put("message","登录失败,密码错误");
                return jsonObject;
            }else {
                String token = tokenManager.createToken(userForBase);
                jsonObject.put("token", token);
                return jsonObject;
            }
        }
    }
    @UserLoginToken
    @GetMapping("/getMessage")
    public String getMessage(){
        return "你已通过验证";
    }

}
