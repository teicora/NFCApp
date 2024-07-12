package com.example.nfcapp

import android.nfc.NfcAdapter
import android.os.Bundle
import android.content.Intent
import android.widget.TextView
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.util.Log
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import java.io.IOException

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.example.nfcapp.ui.theme.NFCAppTheme
import com.google.android.material.dialog.MaterialAlertDialogBuilder

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var textView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        textView = findViewById(R.id.main_text)

        resolveIntent(intent)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {

            return
        }
    }

    public override fun onNewIntent(intent: Intent) {
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
                    techList.contains(NfcA::class.java.name) -> {
                        Log.d("MainActivity", "NfcA tag detected")
                        readNfcA(it)
                    }
                    else -> {
                        Log.d("MainActivity", "Unsupported tag")
                        textView.append("\nUnsupported tag")
                    }
                }
            }
        }
    }
    private fun readMifareClassic(tag: Tag) {
        val mifareClassic = MifareClassic.get(tag)
        try {
            mifareClassic.connect()
            val sectorCount = mifareClassic.sectorCount
            val sb = StringBuilder()
            for (sector in 0 until sectorCount) {
                if (mifareClassic.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT)) {
                    val blockCount = mifareClassic.getBlockCountInSector(sector)
                    val blockIndex = mifareClassic.sectorToBlock(sector)
                    for (block in 0 until blockCount) {
                        val data = mifareClassic.readBlock(blockIndex + block)
                        sb.append("Sector $sector Block ${blockIndex + block} : ${data.toHexString()}\n")
                    }
                } else {
                    sb.append("Sector $sector : Authentication Failed\n")
                }
            }
            textView.text = sb.toString()
        } catch (e: Exception) {
            textView.text = "Error reading MIFARE Classic card: ${e.message}"
        } finally {
            Log.d("MainActivity", "Empty card")
            mifareClassic.close()
        }
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }

    private fun readIsoDep(tag: Tag) {
        val isoDep = IsoDep.get(tag)
        if (isoDep != null) {
            try {
                isoDep.connect()
                val command = byteArrayOf(
                    0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(),
                    0x07.toByte(), 0xD2.toByte(), 0x76.toByte(), 0x00.toByte(),
                    0x00.toByte(), 0x85.toByte(), 0x01.toByte(), 0x01.toByte(),
                    0x00.toByte()
                ) // Пример APDU команды
                val response = isoDep.transceive(command)
                val responseString = response.toHexString()
                textView.append("\nIsoDep Response: $responseString")
                Log.d("MainActivity", "IsoDep Response: $responseString")
            } catch (e: IOException) {
                textView.text = "Error reading IsoDep card: ${e.message}"
                Log.e("MainActivity", "Error reading IsoDep card", e)
            } finally {
                try {
                    isoDep.close()
                } catch (e: IOException) {
                    textView.text = "Error closing IsoDep card: ${e.message}"
                    Log.e("MainActivity", "Error closing IsoDep card", e)
                }
            }
        } else {
            textView.text = "Error: IsoDep tag is null"
            Log.e("MainActivity", "Error: IsoDep tag is null")
        }
    }

    private fun readNfcA(tag: Tag) {
        val nfcA = NfcA.get(tag)
        if (nfcA != null) {
            try {
                nfcA.connect()
                val atqa = nfcA.atqa
                val sak = nfcA.sak
                val atqaString = atqa.toHexString()
                textView.append("\nNfcA ATQA: $atqaString, SAK: $sak")
                Log.d("MainActivity", "NfcA ATQA: $atqaString, SAK: $sak")
            } catch (e: IOException) {
                textView.text = "Error reading NfcA card: ${e.message}"
                Log.e("MainActivity", "Error reading NfcA card", e)
            } finally {
                try {
                    nfcA.close()
                } catch (e: IOException) {
                    textView.text = "Error closing NfcA card: ${e.message}"
                    Log.e("MainActivity", "Error closing NfcA card", e)
                }
            }
        } else {
            textView.text = "Error: NfcA tag is null"
            Log.e("MainActivity", "Error: NfcA tag is null")
        }
    }
}

