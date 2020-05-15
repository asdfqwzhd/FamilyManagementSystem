package com.familymanagementsystem.common.entity;

import lombok.Data;

@Data
public class Member {

	private Long familySeq;

	private Long memberSeq;

	private String name;

	private Integer age;
}
