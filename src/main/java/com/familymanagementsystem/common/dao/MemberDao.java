package com.familymanagementsystem.common.dao;

import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import com.familymanagementsystem.common.entity.Member;

@Mapper
@Repository
public interface MemberDao {

	public Member selectById(Long familySeq, Long memberSeq);
}
