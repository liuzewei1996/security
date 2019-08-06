package com.liu.security.dao;

import com.liu.security.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    User selectByName(String username);

}
