package com.poly.intelligentmessaging.mailserver.controllers

import com.poly.intelligentmessaging.mailserver.domain.dto.*
import com.poly.intelligentmessaging.mailserver.services.AdminService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import org.springframework.web.multipart.MultipartFile

@RestController
@RequestMapping("/admin")
class AdminController {

    @Autowired
    private val adminService: AdminService? = null

    @PostMapping("/setup", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun setup(@RequestBody responseDTO: ResponseDTO): ResponseEntity<ResponseDTO> {
        return ResponseEntity(adminService!!.setup(responseDTO), HttpStatus.OK)
    }

    @PostMapping("/change", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun change(@RequestBody responseDTO: ResponseDTO): ResponseEntity<ResponseDTO> {
        return ResponseEntity(adminService!!.change(responseDTO), HttpStatus.OK)
    }

    @PostMapping("/reject", produces = [MediaType.APPLICATION_JSON_VALUE])
    fun reject(@RequestBody responseDTO: ResponseDTO): ResponseEntity<ResponseDTO> {
        return ResponseEntity(adminService!!.reject(responseDTO), HttpStatus.OK)
    }

    @GetMapping("/getAccessList")
    fun getAccessList(): ResponseEntity<Set<AccessDTO>> {
        return ResponseEntity(adminService!!.getAccessList(), HttpStatus.OK)
    }

    @GetMapping("/getRoles")
    fun getRoles(): ResponseEntity<Set<RoleDTO>> {
        return ResponseEntity(adminService!!.getRoles(), HttpStatus.OK)
    }

    @PostMapping("/update")
    fun update(@RequestParam("file") file: MultipartFile): ResponseEntity<Map<String, String>> {
        return ResponseEntity(adminService!!.updateDB(file), HttpStatus.OK)
    }

    @GetMapping("/getUsers")
    fun getUsers(): ResponseEntity<Set<UserDTO>> {
        return ResponseEntity(adminService!!.getUsers(), HttpStatus.OK)
    }

    @PostMapping("/changeRoles")
    fun changeRoles(@RequestBody changeStaffDTO: ChangeStaffDTO): ResponseEntity<ChangeStaffDTO> {
        return ResponseEntity(adminService!!.changeRoles(changeStaffDTO), HttpStatus.OK)
    }

    @PostMapping("/deleteUser")
    fun deleteUser(@RequestBody changeStaffDTO: ChangeStaffDTO): ResponseEntity<ChangeStaffDTO> {
        return ResponseEntity(adminService!!.deleteUser(changeStaffDTO), HttpStatus.OK)
    }
}
