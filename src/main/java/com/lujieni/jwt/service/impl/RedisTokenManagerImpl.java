package com.lujieni.jwt.service.impl;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.lujieni.jwt.consts.JwtConstants;
import com.lujieni.jwt.entity.User;
import com.lujieni.jwt.service.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class RedisTokenManagerImpl implements TokenManager {
    @Autowired
    private RedisTemplate<Object,Object> redisTemplate;
    @Override
    public String createToken(User user){
        /*REDIS_TOKEN_PREFIX_ID*/
        String key = JwtConstants.REDIS_TOKEN_PREFIX + user.getId();
        Map<String, Object> headerMap = new HashMap<>();
        headerMap.put("alg", "HS256");
        headerMap.put("typ", "JWT");
        /*
           使用用户id当做audience的值,使用用户的密码作秘钥
         */
        String token= JWT.create().withHeader(headerMap) // 设置头部信息 Header
                                  .withIssuer("SERVER")  // 设置载荷签名是有谁生成例如:服务器
                                  .withAudience(user.getId().toString()) // 设置谁接受签名
                                  .withClaim("userId",user.getId()) // 设置自定义信息
                                  .sign(Algorithm.HMAC256(user.getPassword()));// 签名
        redisTemplate.opsForValue().set(key,token,JwtConstants.TOKEN_EXPIRES_MINUTE, TimeUnit.MINUTES);//存入redis
        return token;
    }

    @Override
    public boolean checkToken(String checkToken){
        if (checkToken == null) {
            return false;
        }
        String userId = JWT.decode(checkToken).getAudience().get(0);
        String key = JwtConstants.REDIS_TOKEN_PREFIX + userId;
        String token = (String)redisTemplate.opsForValue().get(key);
        if (token == null || !token.equals(checkToken)) {
            return false;
        }
        redisTemplate.expire(key,JwtConstants.TOKEN_EXPIRES_MINUTE,TimeUnit.MINUTES);
        return true;
    }


    @Override
    public boolean deleteToken(String deleteToken){
        if(deleteToken == null)
            return false;
        String id = JWT.decode(deleteToken).getAudience().get(0);
        String key = JwtConstants.REDIS_TOKEN_PREFIX + id;
        String token = (String)redisTemplate.opsForValue().get(key);
        if (token == null || !token.equals(deleteToken)) {
            return false;
        }
        redisTemplate.delete(key);
        return true;
    }

}
