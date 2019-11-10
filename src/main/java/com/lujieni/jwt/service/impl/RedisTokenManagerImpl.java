package com.lujieni.jwt.service.impl;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.lujieni.jwt.consts.JwtConstants;
import com.lujieni.jwt.entity.User;
import com.lujieni.jwt.service.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RedisTokenManagerImpl implements TokenManager {
    @Autowired
    private RedisTemplate<Object,Object> redisTemplate;
    @Override
    public String createToken(User user){
        /*REDIS_TOKEN_PREFIX_ID*/
        String key = JwtConstants.REDIS_TOKEN_PREFIX+user.getId();
        /*
           使用用户id当做audience的值,使用用户的密码作秘钥
         */
        String token= JWT.create().withAudience(user.getId().toString())
                .sign(Algorithm.HMAC256(user.getPassword()));
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
