package com.awscognito.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.awscognito.model.UserInfo;
import com.awscognito.model.UserSignUpRequest;

@Repository
public interface UserRepo extends JpaRepository<UserInfo, Integer> 
{

	void save(UserSignUpRequest userReq);
    	
  
}
