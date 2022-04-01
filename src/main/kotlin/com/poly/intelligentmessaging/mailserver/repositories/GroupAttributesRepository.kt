package com.poly.intelligentmessaging.mailserver.repositories

import com.poly.intelligentmessaging.mailserver.domain.models.GroupAttributesModel
import com.poly.intelligentmessaging.mailserver.domain.projections.GroupAttributeProjection
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.util.*

@Repository
interface GroupAttributesRepository : JpaRepository<GroupAttributesModel, UUID> {

    @Modifying
    @Query(
        """
            select
                cast(ga.id as varchar),
                ga.name as groupName,
                string_agg(a.name, '|') as attributes
            from group_attributes ga
            inner join attribute a on ga.id = a.id_group_attribute
            group by ga.name, ga.id;
        """,
        nativeQuery = true
    )
    fun getGroupAttributes(): MutableList<GroupAttributeProjection>


    fun findByName(name: String): GroupAttributesModel
}