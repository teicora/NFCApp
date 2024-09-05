package com.example.nfcapp

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private lateinit var textView: TextView
    private lateinit var pendingIntent: PendingIntent
    private lateinit var intentFiltersArray: Array<IntentFilter>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        textView = findViewById(R.id.main_text)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            textView.text = "NFC не поддерживается на этом устройстве."
            return
        }

        // Инициализация PendingIntent для обработки NFC-интентов
        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE)

        // Создание фильтра для обработки NFC
        val ndef = IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED).apply {
            try {
                addDataType("*/*")
            } catch (e: IntentFilter.MalformedMimeTypeException) {
                throw RuntimeException("Не удалось добавить MIME тип.", e)
            }
        }

        intentFiltersArray = arrayOf(ndef)

        // Авторизация при создании активности, если тег уже подключен
        resolveIntent(intent)
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
                textView.text = "Поддерживаемые технологии: $techListString"
                if (techList.contains(MifareClassic::class.java.name)) {
                    Log.d("MainActivity", "Обнаружен тег MifareClassic")
                    val mifareClassic = MifareClassic.get(it)
                    try {
                        mifareClassic.connect()
                        val sectorIndex = 1
                        val blockIndex = mifareClassic.sectorToBlock(sectorIndex) + 1

                        // Аутентификация сектора с ключом A
                        val auth = mifareClassic.authenticateSectorWithKeyA(sectorIndex, MifareClassic.KEY_DEFAULT)
                        if (auth) {
                            // Чтение данных из блока
                            val data = mifareClassic.readBlock(blockIndex)
                            textView.append("\nДанные считаны: ${data.toHexString()}")
                        } else {
                            textView.append("\nОшибка аутентификации для сектора $sectorIndex")
                        }
                    } catch (e: IOException) {
                        textView.text = "Ошибка подключения: ${e.message}"
                    } finally {
                        try {
                            mifareClassic.close()
                        } catch (e: IOException) {
                            Log.e("MainActivity", "Ошибка при закрытии MifareClassic", e)
                        }
                    }
                } else {
                    textView.append("\nНеподдерживаемый тег")
                }
            }
        }
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
