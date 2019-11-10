package com.lujieni.jwt.interceptors;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.lujieni.jwt.annotation.PassToken;
import com.lujieni.jwt.annotation.UserLoginToken;
import com.lujieni.jwt.dao.UserRepository;
import com.lujieni.jwt.service.TokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

public class AuthenticationInterceptor implements HandlerInterceptor {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenManager tokenManager;
    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object) throws Exception {
        /* 从http请求头中取出 token */
        String token = httpServletRequest.getHeader("token");
        // 如果不是映射到方法直接通过
        if(!(object instanceof HandlerMethod)){
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod)object;
        Method method = handlerMethod.getMethod();
        //检查是否有passtoken注释，有则跳过认证
        if (method.isAnnotationPresent(PassToken.class)) {
            PassToken passToken = method.getAnnotation(PassToken.class);
            if (passToken.required()) {
                return true;
            }
        }
        //检查有没有需要用户权限的注解
        if (method.isAnnotationPresent(UserLoginToken.class)) {
            UserLoginToken userLoginToken = method.getAnnotation(UserLoginToken.class);
            if (userLoginToken.required()) {
                if(!tokenManager.checkToken(token)){
                    /* token校验失败 */
                    throw new RuntimeException("token校验失败");
                }
              /*
                    校验token的合法性,因为目前使用redis存储,所以不需要了
                    String id;
                    try {
                        id = JWT.decode(token).getAudience().get(0);
                    } catch (JWTDecodeException j) {
                        throw new RuntimeException("401");
                    }
                    User user = userRepository.findById(Integer.parseInt(userId)).orElse(null);
                    if (user == null) {
                        throw new RuntimeException("用户不存在，请重新登录");
                    }
                    // 验证 token
                    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256(user.getPassword())).build();
                    try {
                        jwtVerifier.verify(token);
                    } catch (JWTVerificationException e) {
                        throw new RuntimeException("401");
                    }
                */
                return true;
            }
        }
        return true;
    }

}
