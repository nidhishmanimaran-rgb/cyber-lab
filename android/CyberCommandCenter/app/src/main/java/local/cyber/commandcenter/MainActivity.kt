package local.cyber.commandcenter

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.InputType
import android.util.Base64
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.res.ResourcesCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.activity.OnBackPressedCallback
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.divider.MaterialDivider
import org.json.JSONObject
import java.security.KeyStore
import java.net.HttpURLConnection
import java.net.URL
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private lateinit var contentArea: LinearLayout
    private lateinit var toolbarTitle: TextView
    private lateinit var statusIndicator: TextView
    private lateinit var bottomNav: BottomNavigationView
    
    private data class NavState(val pageId: Int, val params: Any? = null)
    private val navStack = mutableListOf<NavState>()
    private val PAGE_DEVICE_DETAIL = 1001
    private val PAGE_APK_DETAIL = 1002
    private val PAGE_WEBSEC_DETAIL = 1003
    private val PAGE_MANAGED_DEVICES = 1004
    private val PAGE_MANAGED_DEVICE_DETAIL = 1005
    private val PAGE_RULES = 1006
    private val PAGE_ACTIVITY_LOG = 1007
    private val PAGE_SETTINGS = 1008

    private var currentPageId = R.id.nav_home
    private var isActionProcessing = false
    private var isRunning = true
    private val defaultBackendUrl = "http://192.168.1.2:8001/"
    private val preferenceName = "ccc"
    private val encryptedTokenKey = "apiTokenEncrypted"
    private val legacyTokenKey = "apiToken"
    private val tokenKeyAlias = "ccc_api_token_key"

    // Premium Color System
    private val COLOR_BG = Color.parseColor("#121212")
    private val COLOR_SURFACE = Color.parseColor("#1A1A1A")
    private val COLOR_SURFACE_SECONDARY = Color.parseColor("#202020")
    private val COLOR_DIVIDER = Color.parseColor("#2A2A2A")
    private val COLOR_TEXT_PRIMARY = Color.parseColor("#FFFFFF")
    private val COLOR_TEXT_SECONDARY = Color.parseColor("#A7A7A7")
    private val COLOR_ACCENT = Color.parseColor("#FF6B35")
    private val COLOR_SUCCESS = Color.parseColor("#35C759")
    private val COLOR_WARNING = Color.parseColor("#FFB020")
    private val COLOR_DANGER = Color.parseColor("#FF453A")
    private val COLOR_CRITICAL = Color.parseColor("#FF2D55")

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.AppTheme)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        
        val root = RelativeLayout(this).apply {
            setBackgroundColor(COLOR_BG)
        }

        // Compact Modern Toolbar
        val appBar = LinearLayout(this).apply {
            id = View.generateViewId()
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(24), dp(20), dp(24), dp(12))
            
            // App Logo
            addView(ImageView(context).apply {
                setImageResource(R.drawable.ic_logo_shield)
                layoutParams = LinearLayout.LayoutParams(dp(24), dp(24)).apply {
                    setMargins(0, 0, dp(12), 0)
                }
            })

            toolbarTitle = TextView(context).apply {
                text = "Home"
                setTextColor(COLOR_TEXT_PRIMARY)
                textSize = 22f
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            }
            addView(toolbarTitle)

            statusIndicator = TextView(context).apply {
                text = "● Offline"
                setTextColor(COLOR_TEXT_SECONDARY)
                textSize = 12f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
                setPadding(dp(8), 0, 0, 0)
            }
            addView(statusIndicator)
        }
        val appBarLp = RelativeLayout.LayoutParams(-1, -2).apply {
            addRule(RelativeLayout.ALIGN_PARENT_TOP)
        }
        root.addView(appBar, appBarLp)

        // Modern Bottom Navigation
        bottomNav = BottomNavigationView(this).apply {
            id = View.generateViewId()
            inflateMenu(R.menu.bottom_nav)
            setBackgroundColor(COLOR_SURFACE)
            itemIconTintList = createNavColorStateList()
            itemTextColor = createNavColorStateList()
            labelVisibilityMode = BottomNavigationView.LABEL_VISIBILITY_LABELED
            elevation = dp(8).toFloat()
            
            setOnItemSelectedListener { item ->
                if (currentPageId != item.itemId) {
                    currentPageId = item.itemId
                    refreshPage()
                }
                true
            }
        }
        val navLp = RelativeLayout.LayoutParams(-1, -2).apply {
            addRule(RelativeLayout.ALIGN_PARENT_BOTTOM)
        }
        root.addView(bottomNav, navLp)

        // Handle Window Insets
        ViewCompat.setOnApplyWindowInsetsListener(root) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
            appBar.setPadding(dp(24), dp(20) + insets.top, dp(24), dp(12))
            bottomNav.setPadding(0, dp(8), 0, dp(8) + insets.bottom)
            windowInsets
        }

        // Scrollable Content
        val scrollView = ScrollView(this).apply {
            id = View.generateViewId()
            clipToPadding = false
            overScrollMode = View.OVER_SCROLL_NEVER
            contentArea = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(24), dp(8), dp(24), dp(32))
            }
            addView(contentArea)
        }
        val scrollLp = RelativeLayout.LayoutParams(-1, -1).apply {
            addRule(RelativeLayout.BELOW, appBar.id)
            addRule(RelativeLayout.ABOVE, bottomNav.id)
        }
        root.addView(scrollView, scrollLp)

        setContentView(root)

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (navStack.size > 1) {
                    navStack.removeAt(navStack.size - 1)
                    val state = navStack.last()
                    currentPageId = state.pageId
                    // Update bottom nav selection without triggering listener
                    bottomNav.setOnItemSelectedListener(null)
                    if (state.pageId in listOf(R.id.nav_home, R.id.nav_network, R.id.nav_security, R.id.nav_alerts, R.id.nav_more)) {
                        bottomNav.selectedItemId = state.pageId
                    }
                    bottomNav.setOnItemSelectedListener { item -> onNavItemSelected(item.itemId); true }
                    refreshPage(state.params)
                } else {
                    if (currentPageId != R.id.nav_home) {
                        navigateTo(R.id.nav_home)
                    } else {
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                    }
                }
            }
        })

        navStack.add(NavState(R.id.nav_home))
        refreshPage()
        startHeartbeat()
    }

    private fun onNavItemSelected(itemId: Int) {
        if (currentPageId != itemId) {
            navStack.clear()
            navStack.add(NavState(R.id.nav_home))
            if (itemId != R.id.nav_home) {
                navStack.add(NavState(itemId))
            }
            currentPageId = itemId
            refreshPage()
        }
    }

    private fun navigateTo(pageId: Int, params: Any? = null) {
        if (currentPageId == pageId && (params == null || navStack.lastOrNull()?.params == params)) {
            refreshPage(params)
            return
        }
        currentPageId = pageId
        navStack.add(NavState(pageId, params))
        if (pageId in listOf(R.id.nav_home, R.id.nav_network, R.id.nav_security, R.id.nav_alerts, R.id.nav_more)) {
            bottomNav.setOnItemSelectedListener(null)
            bottomNav.selectedItemId = pageId
            bottomNav.setOnItemSelectedListener { item -> onNavItemSelected(item.itemId); true }
        }
        refreshPage(params)
    }

    private fun dp(v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun createNavColorStateList() = ColorStateList(
        arrayOf(intArrayOf(android.R.attr.state_selected), intArrayOf()),
        intArrayOf(COLOR_ACCENT, COLOR_TEXT_SECONDARY)
    )

    private fun refreshPage(params: Any? = null) {
        if (isFinishing || isDestroyed) return
        contentArea.removeAllViews()
        when (currentPageId) {
            R.id.nav_home -> { toolbarTitle.text = "Home"; renderHome() }
            R.id.nav_network -> { toolbarTitle.text = "Network"; renderNetwork() }
            R.id.nav_security -> { toolbarTitle.text = "Security"; renderSecurity() }
            R.id.nav_alerts -> { toolbarTitle.text = "Alerts"; renderAlerts() }
            R.id.nav_more -> { toolbarTitle.text = "More"; renderMore() }
            PAGE_DEVICE_DETAIL -> { toolbarTitle.text = "Device Details"; renderDeviceDetail(params as JSONObject) }
            PAGE_APK_DETAIL -> { toolbarTitle.text = "App Security"; renderApk() }
            PAGE_WEBSEC_DETAIL -> { toolbarTitle.text = "Web Security"; renderWebSec() }
            PAGE_MANAGED_DEVICES -> { toolbarTitle.text = "Managed Devices"; renderManagedDevices() }
            PAGE_MANAGED_DEVICE_DETAIL -> { toolbarTitle.text = "Device Security"; renderManagedDeviceDetail(params as String) }
            PAGE_RULES -> { toolbarTitle.text = "Protection Rules"; renderRules() }
            PAGE_ACTIVITY_LOG -> { toolbarTitle.text = "Security Events"; renderFullActivity() }
            PAGE_SETTINGS -> { toolbarTitle.text = "Connection Settings"; renderSettings() }
        }
    }

    private fun getBackendUrl() = getSharedPreferences(preferenceName, MODE_PRIVATE).getString("backend", defaultBackendUrl)?.trimEnd('/') ?: ""

    private fun getToken(): String {
        val preferences = getSharedPreferences(preferenceName, MODE_PRIVATE)
        val encrypted = preferences.getString(encryptedTokenKey, "") ?: ""
        if (encrypted.isNotEmpty()) return decryptToken(encrypted)
        val legacy = preferences.getString(legacyTokenKey, "") ?: ""
        if (legacy.isNotEmpty()) {
            saveToken(legacy)
            preferences.edit().remove(legacyTokenKey).apply()
        }
        return legacy
    }

    private fun saveToken(token: String) {
        val preferences = getSharedPreferences(preferenceName, MODE_PRIVATE)
        if (token.isBlank()) {
            preferences.edit().remove(encryptedTokenKey).remove(legacyTokenKey).apply()
            return
        }
        preferences.edit().putString(encryptedTokenKey, encryptToken(token)).remove(legacyTokenKey).apply()
    }

    private fun tokenKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = keyStore.getEntry(tokenKeyAlias, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(
                KeyGenParameterSpec.Builder(
                    tokenKeyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
    }

    private fun encryptToken(token: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, tokenKey())
        val payload = cipher.iv + cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    private fun decryptToken(value: String): String = try {
        val payload = Base64.decode(value, Base64.NO_WRAP)
        require(payload.size > 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, tokenKey(), javax.crypto.spec.GCMParameterSpec(128, payload.copyOfRange(0, 12)))
        String(cipher.doFinal(payload.copyOfRange(12, payload.size)), Charsets.UTF_8)
    } catch (_: Exception) {
        getSharedPreferences(preferenceName, MODE_PRIVATE).edit().remove(encryptedTokenKey).apply()
        ""
    }

    private fun renderHome() {
        val hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)
        val greeting = when(hour) { in 0..11 -> "Good morning"; in 12..16 -> "Good afternoon"; else -> "Good evening" }
        
        contentArea.addView(TextView(this).apply {
            text = greeting
            setTextColor(COLOR_TEXT_SECONDARY)
            textSize = 14f
        })
        contentArea.addView(TextView(this).apply {
            text = "Your security summary"
            setTextColor(COLOR_TEXT_PRIMARY)
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(24))
        })

        val loading = statusMessage("Checking security status...")
        contentArea.addView(loading)

        thread {
            try {
                val stats = getJson("${getBackendUrl()}/api/stats", getToken())
                handler.post {
                    contentArea.removeView(loading)
                    val riskLevel = stats.optString("overall_lab_risk", "UNKNOWN")
                    val riskScore = stats.optInt("lab_risk_score", 0)
                    
                    contentArea.addView(createRiskCard(riskLevel, riskScore))
                    contentArea.addView(sectionHeader("Security areas"))
                    
                    val grid = GridLayout(this).apply {
                        columnCount = 2
                        useDefaultMargins = false
                        layoutParams = LinearLayout.LayoutParams(-1, -2)
                    }
                    grid.addView(overviewStat("Devices found", "${stats.optInt("network_devices")}", 0))
                    grid.addView(overviewStat("Things to review", "${stats.optInt("active_alerts")}", 1))
                    grid.addView(overviewStat("App scans", "${stats.optInt("apks_scanned")}", 2))
                    grid.addView(overviewStat("Web findings", "${stats.optInt("web_findings")}", 3))
                    contentArea.addView(grid)

                    val recent = stats.optJSONArray("recent_activity")
                    if (recent != null && recent.length() > 0) {
                        contentArea.addView(sectionHeader("Recent events"))
                        for (i in 0 until Math.min(recent.length(), 5)) {
                            contentArea.addView(activityRow(recent.getJSONObject(i)))
                        }
                    }
                }
            } catch (e: Exception) {
                handler.post { contentArea.removeView(loading); contentArea.addView(errorState(e.message)) }
            }
        }
    }

    private fun createRiskCard(level: String, score: Int) = MaterialCardView(this).apply {
        radius = dp(16).toFloat()
        setCardBackgroundColor(COLOR_SURFACE)
        strokeWidth = 0
        cardElevation = 0f
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, dp(24)) }
        
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(24))
            
            val info = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
                addView(TextView(context).apply {
                    text = "PROTECTION STATUS"
                    setTextColor(COLOR_TEXT_SECONDARY)
                    textSize = 11f
                    typeface = Typeface.DEFAULT_BOLD
                    letterSpacing = 0.05f
                })
                addView(TextView(context).apply {
                    text = when(level.uppercase()) {
                        "LOW", "OK" -> "Everything looks good"
                        "MEDIUM" -> "Needs attention"
                        "HIGH" -> "Action recommended"
                        "CRITICAL" -> "Needs immediate action"
                        else -> "Status unknown"
                    }
                    setTextColor(getRiskColor(level))
                    textSize = 20f
                    typeface = Typeface.DEFAULT_BOLD
                    setPadding(0, dp(2), 0, 0)
                })
                addView(TextView(context).apply {
                    text = "This score is based on the security of your connected lab."
                    setTextColor(COLOR_TEXT_SECONDARY)
                    textSize = 13f
                    setPadding(0, dp(4), 0, 0)
                })
            }
            addView(info)
            
            val scoreBox = FrameLayout(context).apply {
                layoutParams = LinearLayout.LayoutParams(dp(60), dp(60))
                background = ResourcesCompat.getDrawable(resources, R.drawable.circle_outline, null)
                addView(TextView(context).apply {
                    text = "$score/100"
                    setTextColor(COLOR_TEXT_PRIMARY)
                    textSize = 14f
                    typeface = Typeface.DEFAULT_BOLD
                    gravity = Gravity.CENTER
                })
            }
            addView(scoreBox)
        }
        addView(layout)
    }

    private fun overviewStat(label: String, value: String, index: Int) = MaterialCardView(this).apply {
        radius = dp(12).toFloat()
        setCardBackgroundColor(COLOR_SURFACE)
        strokeWidth = 0
        cardElevation = 0f
        
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            addView(TextView(context).apply { text = value; setTextColor(COLOR_TEXT_PRIMARY); textSize = 18f; typeface = Typeface.DEFAULT_BOLD })
            addView(TextView(context).apply { text = label; setTextColor(COLOR_TEXT_SECONDARY); textSize = 12f; setPadding(0, dp(2), 0, 0) })
        }
        addView(layout)
        
        layoutParams = GridLayout.LayoutParams().apply {
            width = 0
            columnSpec = GridLayout.spec(index % 2, 1f)
            rowSpec = GridLayout.spec(index / 2)
            setMargins(if (index % 2 == 0) 0 else dp(6), dp(6), if (index % 2 == 0) dp(6) else 0, dp(6))
        }
    }

    private fun renderNetwork() {
        contentArea.addView(pageHeader("All devices found on your home network"))
        val loading = statusMessage("Looking for devices...")
        contentArea.addView(loading)
        
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/devices", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    contentArea.removeView(loading)
                    if (items == null || items.length() == 0) {
                        contentArea.addView(emptyState("No devices found yet."))
                    } else {
                        for (i in 0 until items.length()) contentArea.addView(deviceRow(items.getJSONObject(i)))
                    }
                }
            } catch (e: Exception) { handler.post { contentArea.removeView(loading); renderError(e.message) } }
        }
    }

    private fun deviceRow(d: JSONObject) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, dp(12), 0, dp(12))
        
        val icon = ImageView(context).apply {
            setImageResource(R.drawable.ic_device)
            imageTintList = ColorStateList.valueOf(COLOR_TEXT_SECONDARY)
            layoutParams = LinearLayout.LayoutParams(dp(40), dp(40)).apply { setMargins(0, 0, dp(16), 0) }
            setPadding(dp(8), dp(8), dp(8), dp(8))
            background = roundRect(COLOR_SURFACE, dp(8))
        }
        addView(icon)

        val info = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            addView(TextView(context).apply {
                text = d.optString("hostname").let { if (it == "null" || it.isEmpty()) "Unknown device" else it }
                setTextColor(COLOR_TEXT_PRIMARY)
                textSize = 16f
                typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            })
            addView(TextView(context).apply {
                val status = if (d.optString("status") == "online") "Available" else "Unavailable"
                text = "$status • ${d.optString("ip_address")}"
                setTextColor(COLOR_TEXT_SECONDARY)
                textSize = 13f
            })
        }
        addView(info)

        val dot = View(context).apply {
            val online = d.optString("status") == "online"
            layoutParams = LinearLayout.LayoutParams(dp(8), dp(8))
            background = GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(if (online) COLOR_SUCCESS else COLOR_DIVIDER) }
        }
        addView(dot)

        setOnClickListener { navigateTo(PAGE_DEVICE_DETAIL, d) }
    }

    private fun renderSecurity() {
        contentArea.addView(pageHeader("Tools to keep you safe"))
        contentArea.addView(menuRow("App Protection", "Check your apps for security risks", R.drawable.ic_shield) { navigateTo(PAGE_APK_DETAIL) })
        contentArea.addView(menuRow("Web Safety", "Review which websites are authorized", R.drawable.ic_security) { navigateTo(PAGE_WEBSEC_DETAIL) })
        contentArea.addView(menuRow("Protection Rules", "The logic we use to protect you", R.drawable.ic_settings) { navigateTo(PAGE_RULES) })
        contentArea.addView(menuRow("Password Education", "Learn about secure passwords", R.drawable.ic_history) { renderPasswords() })
    }

    private fun renderRules() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Protection Rules"
        contentArea.addView(pageHeader("Active security checks"))
        val loading = statusMessage("Loading rules...")
        contentArea.addView(loading)
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/rules", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    contentArea.removeView(loading)
                    if (items == null || items.length() == 0) {
                        contentArea.addView(emptyState("No rules found."))
                    } else {
                        for (i in 0 until items.length()) {
                            val rule = items.getJSONObject(i)
                            contentArea.addView(MaterialCardView(this).apply {
                                radius = dp(12).toFloat()
                                setCardBackgroundColor(COLOR_SURFACE)
                                strokeWidth = 0
                                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, dp(12)) }
                                addView(LinearLayout(context).apply {
                                    orientation = LinearLayout.VERTICAL
                                    setPadding(dp(16), dp(16), dp(16), dp(16))
                                    addView(TextView(context).apply { text = rule.optString("name"); setTextColor(COLOR_TEXT_PRIMARY); textSize = 16f; typeface = Typeface.DEFAULT_BOLD })
                                    addView(TextView(context).apply { text = rule.optString("description"); setTextColor(COLOR_TEXT_SECONDARY); textSize = 13f; setPadding(0, dp(4), 0, 0) })
                                    val sevText = when(rule.optString("severity").uppercase()) {
                                        "CRITICAL" -> "Priority"
                                        "HIGH" -> "Recommended"
                                        else -> "Standard"
                                    }
                                    addView(TextView(context).apply { text = "Check type: $sevText • Security Weight: ${rule.optInt("risk_points")}"; setTextColor(COLOR_ACCENT); textSize = 11f; setPadding(0, dp(8), 0, 0); typeface = Typeface.DEFAULT_BOLD })
                                })
                            })
                        }
                    }
                    contentArea.addView(MaterialButton(this).apply { text = "Back to Security Tools"; setBackgroundColor(COLOR_SURFACE_SECONDARY); setOnClickListener { onBackPressedDispatcher.onBackPressed() } })
                }
            } catch (e: Exception) { handler.post { contentArea.removeView(loading); renderError(e.message) } }
        }
    }

    private fun menuRow(title: String, sub: String, iconRes: Int, action: () -> Unit) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, dp(16), 0, dp(16))
        
        addView(ImageView(context).apply {
            setImageResource(iconRes)
            imageTintList = ColorStateList.valueOf(COLOR_ACCENT)
            layoutParams = LinearLayout.LayoutParams(dp(24), dp(24)).apply { setMargins(0, 0, dp(16), 0) }
        })

        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            addView(TextView(context).apply { text = title; setTextColor(COLOR_TEXT_PRIMARY); textSize = 16f; typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL) })
            addView(TextView(context).apply { text = sub; setTextColor(COLOR_TEXT_SECONDARY); textSize = 13f })
        })

        addView(ImageView(context).apply {
            setImageResource(R.drawable.ic_chevron_right)
            imageTintList = ColorStateList.valueOf(COLOR_DIVIDER)
        })

        setOnClickListener { action() }
    }

    private fun renderAlerts() {
        contentArea.addView(pageHeader("Things that need your attention"))
        val loading = statusMessage("Checking for updates...")
        contentArea.addView(loading)
        
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/alerts", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    contentArea.removeView(loading)
                    var count = 0
                    if (items != null) {
                        for (i in 0 until items.length()) {
                            val a = items.getJSONObject(i)
                            if (a.optString("status") == "active") {
                                contentArea.addView(alertCard(a))
                                count++
                            }
                        }
                    }
                    if (count == 0) contentArea.addView(emptyState("Everything looks good. No issues found."))
                }
            } catch (e: Exception) { handler.post { contentArea.removeView(loading); renderError(e.message) } }
        }
    }

    private fun alertCard(a: JSONObject) = MaterialCardView(this).apply {
        radius = dp(12).toFloat()
        setCardBackgroundColor(COLOR_SURFACE)
        strokeWidth = dp(1)
        strokeColor = Color.argb(40, 255, 255, 255)
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, dp(16)) }
        
        val layout = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            val sev = a.optString("severity").uppercase()
            val friendlySev = when(sev) {
                "CRITICAL" -> "NEEDS IMMEDIATE ACTION"
                "HIGH" -> "ACTION RECOMMENDED"
                "MEDIUM" -> "NEEDS ATTENTION"
                else -> "INFO"
            }
            addView(TextView(context).apply { text = friendlySev; setTextColor(getRiskColor(sev)); textSize = 10f; typeface = Typeface.DEFAULT_BOLD; letterSpacing = 0.05f })
            addView(TextView(context).apply { text = a.optString("title"); setTextColor(COLOR_TEXT_PRIMARY); textSize = 16f; typeface = Typeface.DEFAULT_BOLD; setPadding(0, dp(2), 0, 0) })
            addView(TextView(context).apply { text = a.optString("description"); setTextColor(COLOR_TEXT_SECONDARY); textSize = 14f; setPadding(0, dp(4), 0, dp(12)) })
            
            val managedDeviceId = a.optString("managed_device_id")
            if (managedDeviceId.isNotEmpty() && managedDeviceId != "null") {
                addView(TextView(context).apply { text = "Detected on: $managedDeviceId"; setTextColor(COLOR_TEXT_SECONDARY); textSize = 12f; setPadding(0, 0, 0, dp(12)) })
            }
            
            addView(MaterialButton(context).apply {
                text = "Mark as seen"
                textSize = 12f
                cornerRadius = dp(8)
                setBackgroundColor(COLOR_SURFACE_SECONDARY)
                setOnClickListener {
                    if (isActionProcessing) return@setOnClickListener
                    isActionProcessing = true
                    isEnabled = false
                    thread {
                        try {
                            postJson("${getBackendUrl()}/api/alerts/${a.optInt("id")}/acknowledge", JSONObject(), getToken())
                            handler.post { isActionProcessing = false; refreshPage() }
                        } catch (e: Exception) {
                            handler.post { isActionProcessing = false; isEnabled = true; Toast.makeText(context, "Could not update alert", Toast.LENGTH_SHORT).show() }
                        }
                    }
                }
            })
        }
        addView(layout)
    }

    private fun renderMore() {
        contentArea.addView(pageHeader("More settings and info"))
        contentArea.addView(sectionHeader("Authorized devices"))
        contentArea.addView(menuRow("Manage Devices", "Pairing and device security health", R.drawable.ic_device) { navigateTo(PAGE_MANAGED_DEVICES) })
        contentArea.addView(sectionHeader("Security Activity"))
        contentArea.addView(menuRow("Security Event Log", "Full timeline of security events", R.drawable.ic_history) { navigateTo(PAGE_ACTIVITY_LOG) })
        contentArea.addView(sectionHeader("Connection"))
        contentArea.addView(menuRow("Connection Settings", "Server and API key configuration", R.drawable.ic_settings) { navigateTo(PAGE_SETTINGS) })
        contentArea.addView(sectionHeader("About"))
        contentArea.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(16), 0, dp(32))
            
            addView(ImageView(context).apply {
                setImageResource(R.drawable.ic_logo_shield)
                layoutParams = LinearLayout.LayoutParams(dp(80), dp(80)).apply {
                    setMargins(0, 0, 0, dp(16))
                }
            })

            addView(TextView(context).apply { 
                text = "Cyber Command Center"
                setTextColor(COLOR_TEXT_PRIMARY)
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
                gravity = Gravity.CENTER
            })
            addView(TextView(context).apply { 
                text = "Version 1.0.0"
                setTextColor(COLOR_TEXT_SECONDARY)
                textSize = 13f
                gravity = Gravity.CENTER
                setPadding(0, dp(4), 0, 0)
            })
        })
    }

    private fun renderManagedDevices() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Managed devices"
        contentArea.addView(pageHeader("Devices you have explicitly authorized"))
        val loading = statusMessage("Checking devices...")
        contentArea.addView(loading)
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/managed-devices", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    contentArea.removeView(loading)
                    if (items == null || items.length() == 0) {
                        contentArea.addView(emptyState("No authorized devices yet."))
                    } else {
                        for (i in 0 until items.length()) contentArea.addView(managedDeviceCard(items.getJSONObject(i)))
                    }
                }
            } catch (e: Exception) {
                handler.post { contentArea.removeView(loading); renderError(e.message) }
            }
        }
    }

    private fun managedDeviceCard(d: JSONObject) = MaterialCardView(this).apply {
        radius = dp(12).toFloat()
        setCardBackgroundColor(COLOR_SURFACE)
        strokeWidth = dp(1)
        strokeColor = Color.argb(40, 255, 255, 255)
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, dp(12)) }
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            val risk = d.optJSONObject("risk")
            addView(TextView(context).apply { text = d.optString("device_name"); setTextColor(COLOR_TEXT_PRIMARY); textSize = 17f; typeface = Typeface.DEFAULT_BOLD })
            addView(TextView(context).apply { 
                val status = if (d.optString("status") == "ACTIVE") "ACTIVE" else "NOT CONNECTED"
                text = "${d.optString("platform")}  •  $status"; setTextColor(if (d.optString("status") == "ACTIVE") COLOR_SUCCESS else COLOR_TEXT_SECONDARY); textSize = 13f; setPadding(0, dp(4), 0, 0) 
            })
            addView(TextView(context).apply { 
                val riskLevel = when(risk?.optString("level", "LOW")?.uppercase()) {
                    "LOW", "OK" -> "Safe"
                    "MEDIUM" -> "Warning"
                    "HIGH" -> "Danger"
                    "CRITICAL" -> "Critical"
                    else -> "Unknown"
                }
                text = "Security: $riskLevel  •  ${d.optInt("active_alerts", 0)} items to review"; setTextColor(COLOR_TEXT_SECONDARY); textSize = 13f; setPadding(0, dp(4), 0, dp(8)) 
            })
            addView(TextView(context).apply { text = "Last active: ${d.optString("last_seen", "never").replace("T", " ").take(16)}"; setTextColor(COLOR_TEXT_SECONDARY); textSize = 12f })
        })
        setOnClickListener { navigateTo(PAGE_MANAGED_DEVICE_DETAIL, d.optString("device_id")) }
    }

    private fun statRow(label: String, value: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(8), 0, dp(8))
        addView(TextView(context).apply { text = label; setTextColor(COLOR_TEXT_SECONDARY); textSize = 13f; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        addView(TextView(context).apply { text = value; setTextColor(COLOR_TEXT_PRIMARY); textSize = 14f; typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL); gravity = Gravity.END })
    }

    private fun renderManagedDeviceDetail(deviceId: String) {
        contentArea.removeAllViews()
        toolbarTitle.text = "Device Security"
        val loading = statusMessage("Getting security status...")
        contentArea.addView(loading)
        thread {
            try {
                val d = getJson("${getBackendUrl()}/api/managed-devices/$deviceId", getToken())
                val alertsData = getJson("${getBackendUrl()}/api/managed-devices/$deviceId/alerts?limit=5", getToken())
                
                handler.post {
                    contentArea.removeView(loading)
                    contentArea.addView(pageHeader("Security details for ${d.optString("device_name")}"))
                    val risk = d.optJSONObject("risk")
                    
                    contentArea.addView(sectionHeader("Identification"))
                    val details = listOf(
                        "Device Name" to d.optString("device_name"),
                        "System" to d.optString("platform"),
                        "Connection" to d.optString("status"),
                        "Protection App v" to d.optString("agent_version"),
                        "Security Score" to "${risk?.optInt("score", 0) ?: 0}/100",
                        "Last Active" to d.optString("last_seen", "never").replace("T", " ").take(16)
                    )
                    details.forEach { (label, value) ->
                        contentArea.addView(statRow(label, value))
                    }

                    // Actions Section
                    contentArea.addView(sectionHeader("Security Actions"))
                    val actions = listOf(
                        "REQUEST_HEARTBEAT" to "Check if device is awake",
                        "REQUEST_SYSTEM_INFO" to "Update system details",
                        "REFRESH_TELEMETRY" to "Refresh security data"
                    )
                    val actionGrid = GridLayout(this).apply { columnCount = 1 }
                    actions.forEach { (actionType, actionLabel) ->
                        actionGrid.addView(MaterialButton(this).apply {
                            text = actionLabel
                            textSize = 12f
                            cornerRadius = dp(8)
                            setBackgroundColor(COLOR_SURFACE_SECONDARY)
                            setOnClickListener {
                                if (isActionProcessing) return@setOnClickListener
                                showConfirmation("Confirm Action", "Do you want to request this action on ${d.optString("device_name")}?") {
                                    isActionProcessing = true
                                    isEnabled = false
                                    thread {
                                        try {
                                            postJson("${getBackendUrl()}/api/managed-devices/$deviceId/actions", 
                                                JSONObject().put("action_type", actionType), getToken())
                                            handler.post { 
                                                isActionProcessing = false
                                                isEnabled = true
                                                Toast.makeText(context, "Action successful", Toast.LENGTH_SHORT).show() 
                                            }
                                        } catch (e: Exception) { 
                                            handler.post { 
                                                isActionProcessing = false
                                                isEnabled = true
                                                Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_SHORT).show() 
                                            } 
                                        }
                                    }
                                }
                            }
                            layoutParams = LinearLayout.LayoutParams(-1, dp(48)).apply {
                                setMargins(0, dp(4), 0, dp(4))
                            }
                        })
                    }
                    contentArea.addView(actionGrid)

                    // Recent Alerts
                    contentArea.addView(sectionHeader("Recent items to review"))
                    val alerts = alertsData.optJSONArray("items")
                    if (alerts == null || alerts.length() == 0) {
                        contentArea.addView(TextView(this).apply { text = "Everything looks good here."; setTextColor(COLOR_TEXT_SECONDARY); textSize = 13f; setPadding(0, dp(8), 0, dp(16)) })
                    } else {
                        for (i in 0 until alerts.length()) {
                            contentArea.addView(alertCard(alerts.getJSONObject(i)))
                        }
                    }

                    contentArea.addView(technicalDetails(d))

                    contentArea.addView(MaterialButton(this).apply { 
                        text = "Back to devices"
                        setBackgroundColor(COLOR_SURFACE_SECONDARY)
                        setOnClickListener { onBackPressedDispatcher.onBackPressed() }
                        layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { setMargins(0, dp(32), 0, 0) }
                    })
                }
            } catch (e: Exception) { handler.post { contentArea.removeView(loading); renderError(e.message) } }
        }
    }

    private fun showConfirmation(title: String, message: String, onConfirm: () -> Unit) {
        MaterialAlertDialogBuilder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("Yes, proceed") { _, _ -> onConfirm() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun technicalDetails(data: JSONObject) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(0, dp(32), 0, dp(32))
        addView(TextView(context).apply {
            text = "TECHNICAL DETAILS (ADVANCED)"
            setTextColor(COLOR_TEXT_SECONDARY)
            textSize = 10f
            typeface = Typeface.DEFAULT_BOLD
            setPadding(0, 0, 0, dp(8))
        })
        addView(HorizontalScrollView(context).apply {
            addView(TextView(context).apply {
                text = data.toString(4)
                setTextColor(COLOR_TEXT_SECONDARY)
                textSize = 9f
                typeface = Typeface.MONOSPACE
            })
        })
    }

    private fun renderSettings() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Settings"
        contentArea.addView(pageHeader("Connection to your security server"))
        
        val prefs = getSharedPreferences(preferenceName, MODE_PRIVATE)
        val urlInput = createInput("Security Server Address", getBackendUrl(), defaultBackendUrl)
        val tokenInput = createInput("API Security Key", getToken(), "Your private key", true)
        contentArea.addView(urlInput)
        contentArea.addView(tokenInput)

        val btn = MaterialButton(this).apply {
            text = "Save & Apply Changes"
            setBackgroundColor(COLOR_ACCENT)
            cornerRadius = dp(12)
            setOnClickListener {
                if (isActionProcessing) return@setOnClickListener
                val u = urlInput.findViewWithTag<EditText>("input").text.toString()
                val t = tokenInput.findViewWithTag<EditText>("input").text.toString()
                prefs.edit().putString("backend", u).apply()
                saveToken(t)
                Toast.makeText(context, "Settings updated", Toast.LENGTH_SHORT).show()
                refreshPage()
            }
            layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { setMargins(0, dp(24), 0, 0) }
        }
        contentArea.addView(btn)
        
        contentArea.addView(MaterialButton(this).apply { 
            text = "Back"
            setBackgroundColor(COLOR_SURFACE_SECONDARY)
            setOnClickListener { onBackPressedDispatcher.onBackPressed() }
            layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { setMargins(0, dp(16), 0, 0) }
        })
    }

    private fun renderFullActivity() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Activity Log"
        contentArea.addView(pageHeader("Timeline of security events"))
        val loading = statusMessage("Loading events...")
        contentArea.addView(loading)
        
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/timeline?limit=50", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    contentArea.removeView(loading)
                    if (items != null) for (i in 0 until items.length()) contentArea.addView(activityRow(items.getJSONObject(i), true))
                }
            } catch (e: Exception) { handler.post { contentArea.removeView(loading); renderError(e.message) } }
        }
    }

    private fun renderApk() {
        contentArea.removeAllViews()
        toolbarTitle.text = "App Security"
        contentArea.addView(pageHeader("Latest application scan report"))
        
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/apk", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    if (items == null || items.length() == 0) contentArea.addView(emptyState("No app reports yet."))
                    else {
                        val r = items.getJSONObject(0)
                        contentArea.addView(TextView(this).apply { text = r.optString("filename"); setTextColor(COLOR_TEXT_PRIMARY); textSize = 18f; typeface = Typeface.DEFAULT_BOLD })
                        contentArea.addView(TextView(this).apply { text = "Security Score: ${r.optInt("risk_score")}/100"; setTextColor(COLOR_ACCENT); setPadding(0, dp(4), 0, dp(24)) })
                        val findings = r.optJSONArray("findings")
                        if (findings != null) {
                            contentArea.addView(sectionHeader("Security Findings"))
                            for (j in 0 until findings.length()) contentArea.addView(activityRow(findings.getJSONObject(j)))
                        }
                        contentArea.addView(technicalDetails(r))
                    }
                    contentArea.addView(MaterialButton(this).apply { text = "Back"; setBackgroundColor(COLOR_SURFACE_SECONDARY); setOnClickListener { onBackPressedDispatcher.onBackPressed() } })
                }
            } catch (e: Exception) { renderError(e.message) }
        }
    }

    private fun renderWebSec() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Web Security"
        contentArea.addView(pageHeader("Authorized websites and services"))
        thread {
            try {
                val data = getJson("${getBackendUrl()}/api/websec", getToken())
                val items = data.optJSONArray("items")
                handler.post {
                    if (items == null || items.length() == 0) contentArea.addView(emptyState("No findings reported."))
                    else {
                        val r = items.getJSONObject(0)
                        contentArea.addView(sectionHeader("Scan result: ${r.optString("target")}"))
                        val findings = r.optJSONArray("findings")
                        if (findings != null) for (j in 0 until findings.length()) contentArea.addView(activityRow(findings.getJSONObject(j)))
                        contentArea.addView(technicalDetails(r))
                    }
                    contentArea.addView(MaterialButton(this).apply { text = "Back"; setBackgroundColor(COLOR_SURFACE_SECONDARY); setOnClickListener { onBackPressedDispatcher.onBackPressed() } })
                }
            } catch (e: Exception) { renderError(e.message) }
        }
    }

    private fun renderPasswords() {
        contentArea.removeAllViews()
        toolbarTitle.text = "Password Education"
        contentArea.addView(pageHeader("Learn how your passwords are securely verified"))
        val input = createInput("Enter a test password", "", "Type something here to see the result")
        contentArea.addView(input)
        contentArea.addView(MaterialButton(this).apply {
            text = "Generate Security Hash"
            setBackgroundColor(COLOR_ACCENT)
            setOnClickListener {
                if (isActionProcessing) return@setOnClickListener
                val p = input.findViewWithTag<EditText>("input").text.toString()
                if (p.isEmpty()) return@setOnClickListener
                isActionProcessing = true
                isEnabled = false
                thread {
                    try {
                        postJson("${getBackendUrl()}/api/crypto/hash", JSONObject().put("password", p), getToken())
                        handler.post { 
                            isActionProcessing = false
                            isEnabled = true
                            Toast.makeText(context, "Generated successfully", Toast.LENGTH_SHORT).show() 
                        }
                    } catch (e: Exception) {
                        handler.post {
                            isActionProcessing = false
                            isEnabled = true
                            Toast.makeText(context, "Generation failed", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            }
        })
        contentArea.addView(MaterialButton(this).apply {
            text = "Back"
            setBackgroundColor(COLOR_SURFACE_SECONDARY)
            setOnClickListener { onBackPressedDispatcher.onBackPressed() }
            layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { setMargins(0, dp(16), 0, 0) }
        })
    }

    private fun renderDeviceDetail(d: JSONObject) {
        contentArea.removeAllViews()
        toolbarTitle.text = "Device Details"
        contentArea.addView(pageHeader("Security profile for ${d.optString("hostname").let { if (it == "null" || it.isEmpty()) "Unknown device" else it }}"))
        
        val status = if (d.optString("status") == "online") "Available" else "Unavailable"
        val rows = listOf(
            "Name" to d.optString("hostname", "Unknown"),
            "Address" to d.optString("ip_address"),
            "Hardware ID" to d.optString("mac_address", "n/a"),
            "Manufacturer" to d.optString("vendor", "Unknown"),
            "Last Detected" to d.optString("last_seen").replace("T", " ").take(16),
            "Current Status" to status
        )
        
        rows.forEach { (label, value) ->
            contentArea.addView(LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(12), 0, dp(12))
                addView(TextView(context).apply { text = label; setTextColor(COLOR_TEXT_SECONDARY); textSize = 12f })
                addView(TextView(context).apply { text = value; setTextColor(COLOR_TEXT_PRIMARY); textSize = 16f; setPadding(0, dp(2), 0, 0) })
                addView(MaterialDivider(context).apply { 
                    dividerColor = COLOR_DIVIDER
                }.apply { layoutParams = LinearLayout.LayoutParams(-1, dp(1)).apply { setMargins(0, dp(12), 0, 0) } })
            })
        }

        contentArea.addView(technicalDetails(d))

        contentArea.addView(MaterialButton(this).apply {
            text = "Back to list"
            setBackgroundColor(COLOR_SURFACE_SECONDARY)
            setOnClickListener { 
                onBackPressedDispatcher.onBackPressed()
            }
            layoutParams = LinearLayout.LayoutParams(-1, dp(54)).apply { setMargins(0, dp(32), 0, 0) }
        })
    }

    private fun startHeartbeat() {
        thread {
            while (isRunning) {
                try {
                    val url = getBackendUrl()
                    if (url.isNotEmpty()) {
                        val conn = URL("$url/api/stats").openConnection() as HttpURLConnection
                        conn.connectTimeout = 3000
                        val token = getToken()
                        if (token.isNotEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
                        val code = conn.responseCode
                        handler.post {
                            statusIndicator.text = when {
                                code in 200..299 -> "● Connected"
                                code == 401 -> "● Auth error"
                                else -> "● Offline"
                            }
                            statusIndicator.setTextColor(if (code in 200..299) COLOR_SUCCESS else COLOR_DANGER)
                        }
                    }
                } catch (e: Exception) {
                    handler.post { statusIndicator.text = "● Offline"; statusIndicator.setTextColor(COLOR_DANGER) }
                }
                Thread.sleep(10000)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
    }

    private fun roundRect(color: Int, radius: Int) = GradientDrawable().apply { setColor(color); cornerRadius = radius.toFloat() }

    private fun sectionHeader(title: String) = TextView(this).apply {
        text = title.uppercase()
        setTextColor(COLOR_ACCENT)
        textSize = 11f
        typeface = Typeface.DEFAULT_BOLD
        letterSpacing = 0.1f
        setPadding(0, dp(32), 0, dp(12))
    }

    private fun pageHeader(sub: String) = TextView(this).apply {
        text = sub
        setTextColor(COLOR_TEXT_SECONDARY)
        textSize = 14f
        setPadding(0, 0, 0, dp(24))
    }

    private fun createInput(label: String, value: String, hintText: String, isPassword: Boolean = false) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        addView(TextView(context).apply { text = label; setTextColor(COLOR_TEXT_SECONDARY); textSize = 11f; setPadding(0, 0, 0, dp(8)) })
        addView(EditText(context).apply {
            tag = "input"; setText(value); hint = hintText; setTextColor(COLOR_TEXT_PRIMARY); setHintTextColor(COLOR_DIVIDER)
            setPadding(dp(16), dp(16), dp(16), dp(16)); background = roundRect(COLOR_SURFACE, dp(12))
            if (isPassword) inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        })
        layoutParams = LinearLayout.LayoutParams(-1, -2).apply { setMargins(0, 0, 0, dp(16)) }
    }

    private fun activityRow(ev: JSONObject, showTime: Boolean = false) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(0, dp(12), 0, dp(12))
        val color = getRiskColor(ev.optString("severity", "LOW"))
        addView(View(context).apply { layoutParams = LinearLayout.LayoutParams(dp(8), dp(8)).apply { setMargins(0, 0, dp(16), 0) }; background = roundRect(color, dp(4)) })
        addView(LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            addView(TextView(context).apply {
                val message = ev.optString("message").ifEmpty { ev.optString("description").ifEmpty { ev.optString("title") } }
                text = message
                setTextColor(COLOR_TEXT_PRIMARY)
                textSize = 14f
            })
            if (showTime) addView(TextView(context).apply { text = ev.optString("timestamp").take(16).replace("T", " "); setTextColor(COLOR_TEXT_SECONDARY); textSize = 11f })
        })
    }

    private fun statusMessage(text: String) = TextView(this).apply { setText(text); setTextColor(COLOR_TEXT_SECONDARY); textSize = 14f; gravity = Gravity.CENTER; setPadding(0, dp(48), 0, dp(48)) }

    private fun emptyState(msg: String) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER; setPadding(0, dp(64), 0, 0)
        addView(TextView(context).apply { text = msg; setTextColor(COLOR_TEXT_SECONDARY); textSize = 16f })
    }

    private fun errorState(msg: String?) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        setPadding(0, dp(48), 0, dp(48))
        val authenticationError = msg?.contains("HTTP 401") == true
        addView(TextView(context).apply { 
            text = if (authenticationError) "Please sign in again" else "We can't connect to your PC"
            setTextColor(COLOR_TEXT_PRIMARY); textSize = 18f; typeface = Typeface.DEFAULT_BOLD 
        })
        addView(TextView(context).apply { 
            val explanation = if (authenticationError) {
                "Your security key is missing or invalid. Please update it in Connection Settings."
            } else {
                "Make sure your PC is on and connected to the same network.\n\nDetails: ${msg ?: "Unknown error"}"
            }
            text = explanation; setTextColor(COLOR_TEXT_SECONDARY); textSize = 14f; gravity = Gravity.CENTER; setPadding(0, dp(4), 0, dp(24)) 
        })
        addView(MaterialButton(context).apply {
            text = "Update Connection Settings"; setBackgroundColor(COLOR_SURFACE_SECONDARY)
            setOnClickListener { navigateTo(R.id.nav_more) }
        })
    }

    private fun renderError(msg: String?) { handler.post { contentArea.removeAllViews(); contentArea.addView(errorState(msg)) } }

    private fun getRiskColor(level: String) = when (level.uppercase()) { "LOW", "OK" -> COLOR_SUCCESS; "MEDIUM" -> COLOR_WARNING; "HIGH" -> COLOR_DANGER; "CRITICAL" -> COLOR_CRITICAL; else -> COLOR_TEXT_SECONDARY }

    private class ApiException(val statusCode: Int) : Exception("HTTP $statusCode")

    private fun getJson(url: String, token: String): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        if (token.isNotEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
        val code = conn.responseCode
        if (code !in 200..299) throw ApiException(code)
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }

    private fun postJson(url: String, body: JSONObject, token: String): JSONObject {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 5000
        conn.readTimeout = 5000
        conn.setRequestProperty("Content-Type", "application/json")
        if (token.isNotEmpty()) conn.setRequestProperty("Authorization", "Bearer $token")
        conn.outputStream.use { it.write(body.toString().toByteArray()) }
        val code = conn.responseCode
        if (code !in 200..299) throw ApiException(code)
        val text = conn.inputStream.bufferedReader().use { it.readText() }
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }
}
