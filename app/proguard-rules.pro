# Xposed loads this class by name from app/src/main/assets/xposed_init.
-keep class com.virb3.trustmealready.Main { *; }
-keep class com.virb3.trustmealready.Main$* { *; }

# The Xposed API is compileOnly and provided by the user's hook framework.
-dontwarn de.robv.android.xposed.**
