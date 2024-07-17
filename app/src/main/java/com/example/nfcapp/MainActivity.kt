package com.example.nfcapp

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var textView: TextView
    private lateinit var editTextKey: EditText
    private lateinit var editTextData: EditText
    private lateinit var buttonWrite: Button
    private var isoDep: IsoDep? = null
    private lateinit var pendingIntent: PendingIntent
    private lateinit var intentFiltersArray: Array<IntentFilter>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textView = findViewById(R.id.main_text)
        editTextKey = findViewById(R.id.editTextKey)
        editTextData = findViewById(R.id.editTextData)
        buttonWrite = findViewById(R.id.write)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            textView.text = "NFC не поддерживается на этом устройстве."
            return
        }

        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val flag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE
        } else {
            0
        }
        pendingIntent = PendingIntent.getActivity(this, 0, intent, flag)

        val ndef = IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED).apply {
            try {
                addDataType("*/*")
            } catch (e: IntentFilter.MalformedMimeTypeException) {
                throw RuntimeException("Fail to add MIME type.", e)
            }
        }

        intentFiltersArray = arrayOf(ndef)

        buttonWrite.setOnClickListener {
            val dataToWrite = editTextData.text.toString().toByteArray(Charsets.UTF_8)
            val dataToWritePadded = padOrTrimData(dataToWrite)
            val key = getKeyFromEditTextOrDefault()

            val localIsoDep = isoDep
            if (localIsoDep != null) {
                if (!localIsoDep.isConnected) {
                    try {
                        localIsoDep.connect()
                    } catch (e: IOException) {
                        textView.text = "Ошибка подключения: ${e.message}"
                        return@setOnClickListener
                    }
                }
                writeIsoDep(localIsoDep, dataToWritePadded, key)
            } else {
                textView.text = "NFC тег не подключен"
            }
        }
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, intentFiltersArray, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        resolveIntent(intent)
    }

    private fun resolveIntent(intent: Intent) {
        val validActions = listOf(
            NfcAdapter.ACTION_TAG_DISCOVERED,
            NfcAdapter.ACTION_TECH_DISCOVERED,
            NfcAdapter.ACTION_NDEF_DISCOVERED
        )
        if (intent.action in validActions) {
            val tag: Tag? = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
            tag?.let {
                val techList = it.techList
                val techListString = techList.joinToString(", ")
                textView.text = "Supported Technologies: $techListString"
                when {
                    techList.contains(IsoDep::class.java.name) -> {
                        Log.d("MainActivity", "IsoDep tag detected")
                        isoDep = IsoDep.get(it)
                    }
                    else -> {
                        Log.d("MainActivity", "Unsupported tag")
                        textView.append("\nUnsupported tag")
                    }
                }
            }
        }
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

    private fun writeIsoDep(isoDep: IsoDep, data: ByteArray, key: ByteArray) {
        try {
            val blockNumber = 4 // Номер блока для записи

            // Аутентификация с использованием ключа A
            authenticateWithKeyA(isoDep, blockNumber, key)

            // Запись данных в блок
            writeBlock(isoDep, blockNumber, data)
            textView.append("\nЗапись успешна.")
        } catch (e: Exception) {
            e.printStackTrace()
            textView.append("\nОшибка записи: ${e.message}.")
        } finally {
            try {
                isoDep.close()
            } catch (e: IOException) {
                textView.text = "Error closing IsoDep card: ${e.message}"
                Log.e("MainActivity", "Error closing IsoDep card", e)
            }
        }
    }

    private fun authenticateWithKeyA(isoDep: IsoDep, blockNumber: Int, key: ByteArray) {
        val authCommand = byteArrayOf(
            0x00.toByte(), // CLA
            0x82.toByte(), // INS (Mifare INS_AUTHENTICATE)
            0x00.toByte(), // P1
            blockNumber.toByte(), // P2: номер блока
            0x06.toByte() // Lc: длина ключа (6 байт)
        ) + key
        val response = isoDep.transceive(authCommand)
        if (response.isEmpty() || response[0].toInt() != 0x00) {
            throw Exception("Authentication failed")
        }
    }

    private fun writeBlock(isoDep: IsoDep, blockNumber: Int, data: ByteArray) {
        if (data.size != 16) {
            throw IllegalArgumentException("Data must be 16 bytes long")
        }

        val writeCommand = byteArrayOf(
            0x00.toByte(), // CLA
            0xD6.toByte(), // INS (UPDATE_BINARY)
            0x00.toByte(), // P1
            blockNumber.toByte(), // P2: номер блока
            0x10.toByte() // Lc: длина данных (16 байт)
        ) + data

        val response = isoDep.transceive(writeCommand)
        if (response.isEmpty() || response[0].toInt() != 0x00) {
            throw Exception("Write failed")
        }
    }

    private fun getKeyFromEditTextOrDefault(): ByteArray {
        val keyString = editTextKey.text.toString()
        return if (keyString.isEmpty()) {
            // Использование стандартного ключа, если поле пустое
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        } else {
            // Преобразование строки ключа в байты
            keyString.chunked(2).map { it.toInt(16).toByte() }.toByteArray().copyOf(6) // Должен быть длиной 6 байт
        }
    }

    private fun padOrTrimData(data: ByteArray): ByteArray {
        return when {
            data.isEmpty() -> ByteArray(16) { 0x00.toByte() }
            data.size > 16 -> data.copyOfRange(0, 16)
            data.size < 16 -> data + ByteArray(16 - data.size) { 0x00.toByte() }
            else -> data
        }
    }
}
