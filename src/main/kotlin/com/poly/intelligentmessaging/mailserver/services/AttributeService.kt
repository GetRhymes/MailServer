package com.poly.intelligentmessaging.mailserver.services

import com.poly.intelligentmessaging.mailserver.domain.dto.AttributesDTO
import com.poly.intelligentmessaging.mailserver.domain.dto.NewAttributeDTO
import com.poly.intelligentmessaging.mailserver.domain.models.AttributeModel
import com.poly.intelligentmessaging.mailserver.domain.models.StudentModel
import com.poly.intelligentmessaging.mailserver.repositories.AttributeRepository
import com.poly.intelligentmessaging.mailserver.repositories.GroupAttributesRepository
import com.poly.intelligentmessaging.mailserver.repositories.StaffRepository
import com.poly.intelligentmessaging.mailserver.repositories.StudentRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import java.util.*

@Service
class AttributeService {

    @Autowired
    val attributeRepository: AttributeRepository? = null

    @Autowired
    val studentRepository: StudentRepository? = null

    @Autowired
    val groupAttributesRepository: GroupAttributesRepository? = null

    @Autowired
    val staffRepository: StaffRepository? = null

    fun getAttributes(): List<AttributesDTO> {
        val attributes = attributeRepository!!.getAttributes()
        val listAttributesDTO = mutableMapOf<String, AttributesDTO>()
        for (attribute in attributes) {
            val id = attribute.getId()
            if (listAttributesDTO.containsKey(id)) {
                listAttributesDTO[id]!!.students.add(attribute.getStudentId())
            } else {
                val attributeName = attribute.getAttributeName()
                val groupName = attribute.getGroupName()
                val type = if (attribute.getExpression() == null) "list" else "expression"
                val created = attribute.getCreated().split(" ")[0]
                val attributesDTO = AttributesDTO(id, attributeName, groupName, type, created)
                attributesDTO.students.add(attribute.getStudentId())
                listAttributesDTO[id] = attributesDTO
            }
        }
        return listAttributesDTO.values.toList()
    }

    fun createAttribute(newAttributeDTO: NewAttributeDTO): AttributeModel {
        val setStudents = mutableSetOf<StudentModel>()
        newAttributeDTO.studentsId!!.forEach {
            setStudents.add(studentRepository!!.findById(UUID.fromString(it)).get())
        }
        val groupAttributeModel = groupAttributesRepository!!.findByName(newAttributeDTO.groupName!!)
        val staff = staffRepository!!.findById(UUID.fromString("725cee0f-7a95-4094-b19a-11b27f779490")).get()
        val attributeModel = AttributeModel(
            staff = staff,
            name = newAttributeDTO.name,
            group = groupAttributeModel,
            student = setStudents
        )
        return attributeRepository!!.save(attributeModel)
    }
}