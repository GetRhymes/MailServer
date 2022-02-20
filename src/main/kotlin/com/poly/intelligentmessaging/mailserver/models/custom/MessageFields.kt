package com.poly.intelligentmessaging.mailserver.models.custom

import javax.mail.internet.MimeMultipart

class MessageFields(
    val senderAddress: String,
    var recipientAddress: List<String>?,
    val subject: String,
    var contentMultipart: MimeMultipart? = null,
    var contentString: String? = null
)
