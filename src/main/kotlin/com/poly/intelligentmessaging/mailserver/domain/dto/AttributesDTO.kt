package com.poly.intelligentmessaging.mailserver.domain.dto

data class AttributesDTO(
    val id: String,
    val attributeName: String,
    val groupName: String,
    val type: String,
    val created: String,
    val students: MutableList<String> = mutableListOf()
)