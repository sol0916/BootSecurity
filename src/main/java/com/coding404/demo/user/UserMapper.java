package com.coding404.demo.user;

import org.apache.ibatis.annotations.Mapper;

import com.coding404.demo.command.UserVO;

@Mapper
public interface UserMapper {

	public void join(UserVO vo); //가입
	public UserVO login(String username); //로그인
	
	
}
