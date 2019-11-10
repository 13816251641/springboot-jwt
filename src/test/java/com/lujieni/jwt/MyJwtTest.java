package com.lujieni.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.HashMap;
import java.util.Map;

@RunWith(SpringRunner.class)
@SpringBootTest
public class MyJwtTest {
    private String token;

    /**
     * 创建token
     */
    @Before
    public void createToken() {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("alg", "HS256");//HS256 对称加密算法
        map.put("typ", "JWT");

        /*构建密钥信息 */
        Algorithm algorithm = Algorithm.HMAC256("secret");
        token = JWT.create().withHeader(map)
                .withSubject("测试token")//设置主题
                .withAudience("app")//设置谁接受签名
                .withIssuer("server")//设置签名是由谁生成
                /* 设置 载荷 Payload */
                .withClaim("loginName", "zhuoqianmingyue")
                .withClaim("userName", "张三")
                .withClaim("deptName", "技术部")
                /* 签名 Signature */
                .sign(algorithm);
    }

    /**
     * 直接获取token中的值,发现如下:
     * 1.audience&issuer&subject可直接获取
     * 2.claims里的值无法直接获取
     */
    @Test
    public void testGetValueDirectly(){
        String audience = JWT.decode(token).getAudience().get(0);
        System.out.println("audience:"+audience);
        String issuer = JWT.decode(token).getIssuer();
        System.out.println("issuer:"+issuer);
        String subject = JWT.decode(token).getSubject();
        System.out.println(subject);
        Map<String, Claim> claims = JWT.decode(token).getClaims();
        System.out.println(claims);
    }

    /**
     * 验证token的合法性,只有通过vertify我们才能获取到claim中的值,
     * 但audience&&issuer等参数我们却可以直接获取,见testGetValueDirectly
     */
    @Test
    public void verifyToken() {
        Algorithm algorithm = Algorithm.HMAC256("secret");
        /* reusable verifier instance */
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT jwt = verifier.verify(token);

        Map<String, Claim> claims = jwt.getClaims();
        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            String key = entry.getKey();
            Claim claim = entry.getValue();
            System.out.println("key:" + key + " value:" + claim.asString());
        }
    }

}
