import android.os.Bundle;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.appcompat.app.AppCompatDelegate;
import android.content.Context;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.app.Activity;
import androidx.fragment.app.DialogFragment;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.app.AlertDialog;

// Security Issue: Missing null check on value returned by Android's getSupportActionBar method (CWE-476: NULL Pointer Dereference)

// True Positive Examples (Vulnerable/Insecure Code)

public void bad_case_1(AppCompatActivity activity) {
    // Standard AppCompatActivity usage without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setDisplayHomeAsUpEnabled(true);
}

public void bad_case_2(AppCompatActivity activity) {
    // Setting title without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setTitle("Dashboard");
}

public void bad_case_3(AppCompatActivity activity) {
    // Setting subtitle without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setSubtitle("User Profile");
}

public void bad_case_4(AppCompatActivity activity) {
    // Setting navigation mode without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setDisplayShowHomeEnabled(true);
}

public void bad_case_5(AppCompatActivity activity) {
    // Setting custom view without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setCustomView(R.layout.custom_action_bar);
}

public void bad_case_6(AppCompatActivity activity) {
    // Hiding action bar without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().hide();
}

public void bad_case_7(AppCompatActivity activity) {
    // Showing action bar without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().show();
}

public void bad_case_8(AppCompatActivity activity) {
    // Setting home button enabled without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setHomeButtonEnabled(true);
}

public void bad_case_9(AppCompatActivity activity) {
    // Setting display options without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setDisplayOptions(ActionBar.DISPLAY_SHOW_TITLE);
}

public void bad_case_10(Fragment fragment) {
    // Fragment accessing action bar without null check
    // ruleid: java-checkgetsupportactionbarfornull
    ((AppCompatActivity) fragment.getActivity()).getSupportActionBar().setDisplayHomeAsUpEnabled(true);
}

public void bad_case_11(AppCompatActivity activity) {
    // Setting elevation without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setElevation(4.0f);
}

public void bad_case_12(AppCompatActivity activity) {
    // Setting background drawable without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setBackgroundDrawable(ContextCompat.getDrawable(activity, R.drawable.action_bar_bg));
}

public void bad_case_13(AppCompatActivity activity) {
    // Setting display show custom without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setDisplayShowCustomEnabled(true);
}

public void bad_case_14(AppCompatActivity activity) {
    // Setting display show title without null check
    // ruleid: java-checkgetsupportactionbarfornull
    activity.getSupportActionBar().setDisplayShowTitleEnabled(false);
}

public void bad_case_15(DialogFragment dialogFragment) {
    // DialogFragment accessing action bar without null check
    // ruleid: java-checkgetsupportactionbarfornull
    ((AppCompatActivity) dialogFragment.getActivity()).getSupportActionBar().hide();
}

// True Negative Examples (Safe/Secure Code)

public void good_case_1(AppCompatActivity activity) {
    // Standard AppCompatActivity usage with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setDisplayHomeAsUpEnabled(true);
    }
}

public void good_case_2(AppCompatActivity activity) {
    // Setting title with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setTitle("Dashboard");
    }
}

public void good_case_3(AppCompatActivity activity) {
    // Setting subtitle with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setSubtitle("User Profile");
    }
}

public void good_case_4(AppCompatActivity activity) {
    // Setting navigation mode with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setDisplayShowHomeEnabled(true);
    }
}

public void good_case_5(AppCompatActivity activity) {
    // Setting custom view with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setCustomView(R.layout.custom_action_bar);
    }
}

public void good_case_6(AppCompatActivity activity) {
    // Hiding action bar with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.hide();
    }
}

public void good_case_7(AppCompatActivity activity) {
    // Showing action bar with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.show();
    }
}

public void good_case_8(AppCompatActivity activity) {
    // Setting home button enabled with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setHomeButtonEnabled(true);
    }
}

public void good_case_9(AppCompatActivity activity) {
    // Setting display options with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_TITLE);
    }
}

public void good_case_10(Fragment fragment) {
    // Fragment accessing action bar with null check
    if (fragment.getActivity() instanceof AppCompatActivity) {
        ActionBar actionBar = ((AppCompatActivity) fragment.getActivity()).getSupportActionBar();
        // ok: java-checkgetsupportactionbarfornull
        if (actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
        }
    }
}

public void good_case_11(AppCompatActivity activity) {
    // Setting elevation with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setElevation(4.0f);
    }
}

public void good_case_12(AppCompatActivity activity) {
    // Setting background drawable with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setBackgroundDrawable(ContextCompat.getDrawable(activity, R.drawable.action_bar_bg));
    }
}

public void good_case_13(AppCompatActivity activity) {
    // Setting display show custom with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setDisplayShowCustomEnabled(true);
    }
}

public void good_case_14(AppCompatActivity activity) {
    // Setting display show title with null check
    ActionBar actionBar = activity.getSupportActionBar();
    // ok: java-checkgetsupportactionbarfornull
    if (actionBar != null) {
        actionBar.setDisplayShowTitleEnabled(false);
    }
}

public void good_case_15(DialogFragment dialogFragment) {
    // DialogFragment accessing action bar with null check
    if (dialogFragment.getActivity() instanceof AppCompatActivity) {
        ActionBar actionBar = ((AppCompatActivity) dialogFragment.getActivity()).getSupportActionBar();
        // ok: java-checkgetsupportactionbarfornull
        if (actionBar != null) {
            actionBar.hide();
        }
    }
}