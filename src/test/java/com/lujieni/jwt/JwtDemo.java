package com.lujieni.jwt;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.lujieni.jwt.entity.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;


/**
 * 别人的测试源码
 */
@SpringBootTest
@RunWith(SpringRunner.class)
public class JwtDemo {

    private Logger log = LoggerFactory.getLogger(JwtDemo.class);

    /**
     * 生成不携带自定义信息的JWT token
     */
    public String createToken() {
        String secret = "secret";// token 密钥
        Algorithm algorithm = Algorithm.HMAC256("secret");

        // 头部信息
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        Date nowDate = new Date();
        Date expireDate = getAfterDate(nowDate, 0, 0, 0, 2, 0, 0);// 2小过期

        String token = JWT.create()
                .withHeader(map)// 设置头部信息 Header
                .withIssuer("service")//设置 载荷 签名是有谁生成 例如 服务器
                .withSubject("this is test token")//设置 载荷 签名的主题
                // .withNotBefore(new Date())//设置 载荷 定义在什么时间之前，该jwt都是不可用的.
                .withAudience("APP")//设置 载荷 签名的观众 也可以理解谁接受签名的
                .withIssuedAt(nowDate) //设置 载荷 生成签名的时间
                .withExpiresAt(expireDate)//设置 载荷 签名过期的时间
                .sign(algorithm);//签名 Signature
        return token;
    }

    /**
     * 生成携带自定义信息的JWT token
     */
    @Test
    public void createTokenWithClaim() {
        Map<String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        Date nowDate = new Date();
        Date expireDate = getAfterDate(nowDate,0,0,0,2,0,0);//2小过期

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create()
                .withHeader(map)
                /*设置 载荷 Payload*/
                .withClaim("loginName", "zhuoqianmingyue")
                .withIssuer("service")//签名是有谁生成 例如 服务器
                .withSubject("this is test token")//签名的主题
                //.withNotBefore(new Date())//该jwt都是不可用的时间
                .withAudience("app")//签名的观众 也可以理解谁接受签名的
                .withIssuedAt(nowDate) //生成签名的时间
                .withExpiresAt(expireDate)//签名过期的时间
                /*签名 Signature */
                .sign(algorithm);
    }

    @Test
    public void createTokenWithChineseClaim() {
        Date nowDate = new Date();
        Date expireDate = getAfterDate(nowDate, 0, 0, 0, 2, 0, 0);// 2小过期

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create().withHeader(map)
                /* 设置 载荷 Payload */
                .withClaim("loginName", "zhuoqianmingyue")
                .withClaim("userName", "张三")
                .withClaim("deptName", "技术部")
                .withIssuer("auth0")// 签名是有谁生成 例如 服务器
                .withSubject("this is test token")// 签名的主题
                // .withNotBefore(new Date())//该jwt都是不可用的时间
                .withAudience("app")// 签名的观众 也可以理解谁接受签名的
                .withIssuedAt(nowDate) // 生成签名的时间
                .withExpiresAt(expireDate)// 签名过期的时间
                /* 签名 Signature */
                .sign(algorithm);
    }

    /**
     * 验证token
     * @throws UnsupportedEncodingException
     */
    @Test
    public void verifyToken() throws UnsupportedEncodingException {
        String token = createTokenWithChineseClaim2();

        Algorithm algorithm = Algorithm.HMAC256("secret");
        /*
           如果待验证的token中设置了issuer,构造verifier时要么不设置
           issuer的值,要么一定要和待验证的相匹配才行!!!
         */
        JWTVerifier verifier = JWT.require(algorithm).withIssuer("service").build(); // Reusable verifier instance
        DecodedJWT jwt = verifier.verify(token);

        /*
            有些属性明明没有设置token还会帮我们设置,如exp&iat
            subject:this is test token
            audience:APP
            key:sub value:this is test token
            key:aud value:APP
            key:loginName value:zhuoqianmingyue
            key:iss value:service
            key:exp value:null
            key:user value:eyJ1c2VyTmFtZSI6IuW8oOS4iSIsImRlcHROYW1lIjoi5oqA5pyv6YOoIn0=
            key:iat value:null
         */
        String subject = jwt.getSubject();
        System.out.println("subject:"+subject);
        List<String> audience = jwt.getAudience();
        System.out.println("audience:"+audience.get(0));
        Map<String, Claim> claims = jwt.getClaims();
        for (Entry<String, Claim> entry : claims.entrySet()) {
            String key = entry.getKey();
            Claim claim = entry.getValue();
            System.out.println("key:" + key + " value:" + claim.asString());
        }

        byte[] userByte = BaseEncoding.base64().decode(claims.get("user").asString());
        User user = new Gson().fromJson(new String(userByte), User.class);
        System.out.println(user);
    }


    public String createTokenWithChineseClaim2() throws UnsupportedEncodingException {
        Date nowDate = new Date();
        Date expireDate = getAfterDate(nowDate, 0, 0, 0, 2, 0, 0);// 2小过期

        Map<String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        User user = new User();
        user.setUsername("张三");
        user.setPassword("123");
        Gson gson = new Gson();
        String userJson = gson.toJson(user);
        // String encode = URLEncoder.encode(userJson, "UTF-8");

        String userJsonBase64 = BaseEncoding.base64().encode(userJson.getBytes());

        Algorithm algorithm = Algorithm.HMAC256("secret");
        String token = JWT.create().withHeader(map)
                .withClaim("loginName", "zhuoqianmingyue").withClaim("user", userJsonBase64)
                .withIssuer("service")// 签名是有谁生成
                .withSubject("this is test token")// 签名的主题
                // .withNotBefore(new Date())//该jwt都是不可用的时间
                .withAudience("APP")// 签名的观众 也可以理解谁接受签名的
                .withIssuedAt(nowDate) // 生成签名的时间
                .withExpiresAt(expireDate)// 签名过期的时间
                .sign(algorithm);// 签名 Signature

        return token;
    }












    /**
     * 返回一定时间后的日期
     * @param date 开始计时的时间
     * @param year 增加的年
     * @param month 增加的月
     * @param day 增加的日
     * @param hour 增加的小时
     * @param minute 增加的分钟
     * @param second 增加的秒
     * @return
     */
    public  Date getAfterDate(Date date, int year, int month, int day, int hour, int minute, int second){
        if(date == null){
            date = new Date();
        }

        Calendar cal = new GregorianCalendar ();

        cal.setTime(date);
        if(year != 0){
            cal.add(Calendar.YEAR, year);
        }
        if(month != 0){
            cal.add(Calendar.MONTH, month);
        }
        if(day != 0){
            cal.add(Calendar.DATE, day);
        }
        if(hour != 0){
            cal.add(Calendar.HOUR_OF_DAY, hour);
        }
        if(minute != 0){
            cal.add(Calendar.MINUTE, minute);
        }
        if(second != 0){
            cal.add(Calendar.SECOND, second);
        }
        return cal.getTime();
    }


}
