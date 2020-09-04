package com.scb.loanapi.gateway.serviceimpl;

import java.util.ArrayList;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.scb.loanapi.gateway.model.UserDetail;
import com.scb.loanapi.gateway.repository.LoanUserRepository;
import com.scb.loanapi.gateway.service.LoanUserService;


@Service
public class LoanUserServiceImpl implements LoanUserService {

	@Autowired
	LoanUserRepository loanUserRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetail userDetail = loanUserRepository.findByEmailId(username);

		if (userDetail ==null) {
			throw new UsernameNotFoundException(username);
		}

		return new User(userDetail.getEmailId(), userDetail.getPassword(), true, true, true, true,
				new ArrayList<>());
	}


}
