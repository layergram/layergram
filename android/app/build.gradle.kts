import java.util.Properties

val keystorePropertiesFile = rootProject.file("key.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) {
        load(keystorePropertiesFile.inputStream())
    }
}

val releaseStoreFile = keystoreProperties.getProperty("storeFile")
val releaseStorePassword = keystoreProperties.getProperty("storePassword")
val releaseKeyAlias = keystoreProperties.getProperty("keyAlias")
val releaseKeyPassword = keystoreProperties.getProperty("keyPassword")
val hasReleaseKeystore = keystorePropertiesFile.exists()

fun resolveKeystoreFile(path: String): File {
    val normalizedPath = if (path.startsWith("~/")) {
        System.getProperty("user.home") + path.removePrefix("~")
    } else {
        path
    }
    return File(normalizedPath).let { candidate ->
        if (candidate.isAbsolute) {
            candidate
        } else {
            rootProject.file(normalizedPath)
        }
    }
}

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

dependencies {
    implementation("com.google.android.play:feature-delivery:2.1.0")
    implementation("com.google.android.play:core-common:2.0.3")
}

android {
    namespace = "app.layergram"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    signingConfigs {
        create("release") {
            if (hasReleaseKeystore) {
                require(!releaseStoreFile.isNullOrBlank()) {
                    "Missing 'storeFile' in ${keystorePropertiesFile.path}"
                }
                require(!releaseStorePassword.isNullOrBlank()) {
                    "Missing 'storePassword' in ${keystorePropertiesFile.path}"
                }
                require(!releaseKeyAlias.isNullOrBlank()) {
                    "Missing 'keyAlias' in ${keystorePropertiesFile.path}"
                }
                require(!releaseKeyPassword.isNullOrBlank()) {
                    "Missing 'keyPassword' in ${keystorePropertiesFile.path}"
                }

                val resolvedStoreFile = resolveKeystoreFile(releaseStoreFile)
                require(resolvedStoreFile.exists()) {
                    "Keystore file not found: ${resolvedStoreFile.path}"
                }

                storeFile = resolvedStoreFile
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "app.layergram"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    buildTypes {
        release {
            signingConfig = if (hasReleaseKeystore) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

flutter {
    source = "../.."
}
