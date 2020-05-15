package com.familymanagementsystem.member.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.familymanagementsystem.common.dao.MemberDao;
import com.familymanagementsystem.common.entity.Member;

@RestController
@RequestMapping("/member")
public class MemberController {

	@Autowired
	private MemberDao memberDao;

	@PostMapping
	public Member searchMemberInfo() {
		Member member = memberDao.selectById(1L, 1L);
//		member.getFamilySeq();
		return member;
	}
}
