package com.lujieni.jwt.service;

import com.lujieni.jwt.entity.User;

/**
 * 对token进行操作的接口
 */
public interface TokenManager {
    /**
     * 创建token
     * @param user 用户实体类
     * @return token
     */
    public String createToken(User user);

    /**
     * checkToken有效性
     * @param checkToken 待校验的token
     * @return 是否合法
     */
    public boolean checkToken(String checkToken);


    /**
     * 用户登出删除token
     * @param deleteToken 待删除的token
     * @return 是否删除成功
     */
    public boolean deleteToken(String deleteToken);

}
