package com.example.actionbarapp;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;

public class ActionBarExamples extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    // True Positive Examples (Vulnerable Code)

    public void bad_case_1() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        actionBar.setTitle("My App Title");
    }

    public void bad_case_2() {
        // ruleid: java-checkgetsupportactionbarfornull
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);
    }

    public void bad_case_3() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar bar = getSupportActionBar();
        bar.setDisplayShowHomeEnabled(true);
        bar.setIcon(R.drawable.ic_launcher);
    }

    public void bad_case_4() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (isInPortraitMode()) {
            actionBar.hide();
        } else {
            actionBar.show();
        }
    }

    public void bad_case_5() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar bar = getSupportActionBar();
        bar.setSubtitle("Welcome to my app");
        bar.setDisplayShowTitleEnabled(true);
    }

    public void bad_case_6() {
        boolean showHomeButton = true;
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        actionBar.setDisplayHomeAsUpEnabled(showHomeButton);
        actionBar.setHomeButtonEnabled(showHomeButton);
    }

    public void bad_case_7() {
        String title = getIntent().getStringExtra("TITLE");
        // ruleid: java-checkgetsupportactionbarfornull
        getSupportActionBar().setTitle(title);
    }

    public void bad_case_8() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        for (int i = 0; i < getTabCount(); i++) {
            actionBar.addTab(actionBar.newTab().setText("Tab " + i));
        }
    }

    public void bad_case_9() {
        try {
            // ruleid: java-checkgetsupportactionbarfornull
            ActionBar actionBar = getSupportActionBar();
            actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.action_bar_bg));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_10() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        switch (getCurrentTheme()) {
            case LIGHT:
                actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.light_bg));
                break;
            case DARK:
                actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.dark_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY));
                break;
        }
    }

    public void bad_case_11() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        CustomActionBarConfig config = new CustomActionBarConfig();
        config.applyTo(actionBar);
    }

    public void bad_case_12() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (isUserLoggedIn()) {
            actionBar.setTitle("Welcome " + getCurrentUsername());
        } else {
            actionBar.setTitle("Please Log In");
        }
    }

    public void bad_case_13() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        actionBar.setCustomView(R.layout.custom_action_bar);
        actionBar.setDisplayShowCustomEnabled(true);
    }

    public void bad_case_14() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        MenuItem searchItem = menu.findItem(R.id.search);
        actionBar.setDisplayShowTitleEnabled(!searchItem.isVisible());
    }

    public void bad_case_15() {
        // ruleid: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        int color = isDarkMode() ? getColor(R.color.dark_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY) : getColor(R.color.light_action_bar);
        actionBar.setBackgroundDrawable(new ColorDrawable(color));
    }

    // True Negative Examples (Safe Code)

    public void good_case_1() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setTitle("My App Title");
        }
    }

    public void good_case_2() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }
    }

    public void good_case_3() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar bar = getSupportActionBar();
        if (bar != null) {
            bar.setDisplayShowHomeEnabled(true);
            bar.setIcon(R.drawable.ic_launcher);
        }
    }

    public void good_case_4() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            if (isInPortraitMode()) {
                actionBar.hide();
            } else {
                actionBar.show();
            }
        }
    }

    public void good_case_5() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar bar = getSupportActionBar();
        if (bar != null) {
            bar.setSubtitle("Welcome to my app");
            bar.setDisplayShowTitleEnabled(true);
        }
    }

    public void good_case_6() {
        boolean showHomeButton = true;
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(showHomeButton);
            actionBar.setHomeButtonEnabled(showHomeButton);
        }
    }

    public void good_case_7() {
        String title = getIntent().getStringExtra("TITLE");
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setTitle(title);
        }
    }

    public void good_case_8() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            for (int i = 0; i < getTabCount(); i++) {
                actionBar.addTab(actionBar.newTab().setText("Tab " + i));
            }
        }
    }

    public void good_case_9() {
        try {
            // ok: java-checkgetsupportactionbarfornull
            ActionBar actionBar = getSupportActionBar();
            if (actionBar != null) {
                actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.action_bar_bg));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_10() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            switch (getCurrentTheme()) {
                case LIGHT:
                    actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.light_bg));
                    break;
                case DARK:
                    actionBar.setBackgroundDrawable(getResources().getDrawable(R.drawable.dark_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY));
                    break;
            }
        }
    }

    public void good_case_11() {
        // Using Objects.requireNonNull to ensure actionBar is not null
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = java.util.Objects.requireNonNull(getSupportActionBar());
        CustomActionBarConfig config = new CustomActionBarConfig();
        config.applyTo(actionBar);
    }

    public void good_case_12() {
        // Alternative null check pattern
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (null != actionBar) {
            if (isUserLoggedIn()) {
                actionBar.setTitle("Welcome " + getCurrentUsername());
            } else {
                actionBar.setTitle("Please Log In");
            }
        }
    }

    public void good_case_13() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setCustomView(R.layout.custom_action_bar);
            actionBar.setDisplayShowCustomEnabled(true);
        } else {
            Toast.makeText(this, "ActionBar not available", Toast.LENGTH_SHORT).show();
        }
    }

    public void good_case_14() {
        // ok: java-checkgetsupportactionbarfornull
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            MenuItem searchItem = menu.findItem(R.id.search);
            actionBar.setDisplayShowTitleEnabled(!searchItem.isVisible());
        }
    }

    public void good_case_15() {
        // Using a helper method that handles null check
        // ok: java-checkgetsupportactionbarfornull
        setupActionBar(isDarkMode() ? 
            getColor(R.color.dark_REDAC_REDACTED_TWILIO_ID_STRIPE_KEY) : 
            getColor(R.color.light_action_bar));
    }

    // Helper methods to make the examples work
    private void setupActionBar(int color) {
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            actionBar.setBackgroundDrawable(new ColorDrawable(color));
        }
    }

    private boolean isInPortraitMode() {
        return getResources().getConfiguration().orientation == android.content.res.Configuration.ORIENTATION_PORTRAIT;
    }

    private int getTabCount() {
        return 3;
    }

    private enum Theme {
        LIGHT, DARK
    }

    private Theme getCurrentTheme() {
        return Theme.LIGHT;
    }

    private boolean isUserLoggedIn() {
        return true;
    }

    private String getCurrentUsername() {
        return "User";
    }

    private boolean isDarkMode() {
        return false;
    }

    private class CustomActionBarConfig {
        public void applyTo(ActionBar actionBar) {
            // Apply custom configuration to action bar
        }
    }
}