package com.awscognito.Controller.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.awscognito.model.UserInfo;
import com.awscognito.model.UserSignUpRequest;
import com.awscognito.repository.UserRepo;



@Service
public class UserService {

	@Autowired
	private UserRepo userRepo;
	public void saveUser(UserSignUpRequest userReq)
	{
		UserInfo user=new UserInfo();
		user.setEmail(userReq.getEmail());
		user.setMobile_no(userReq.getMobile_no());
		userRepo.save(user);	  
	}
}
