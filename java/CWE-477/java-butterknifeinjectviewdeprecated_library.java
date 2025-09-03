import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.RatingBar;
import android.widget.WebView;
import android.widget.VideoView;
import android.widget.Switch;
import android.widget.ToggleButton;
import android.widget.CalendarView;
import android.widget.DatePicker;
import android.widget.TimePicker;
import android.widget.NumberPicker;
import android.widget.ScrollView;
import android.widget.HorizontalScrollView;
import android.widget.TabHost;
import android.widget.ViewFlipper;
import android.widget.ViewSwitcher;
import android.widget.TextSwitcher;
import android.widget.ImageSwitcher;
import android.widget.Chronometer;
import android.widget.AnalogClock;
import android.widget.DigitalClock;
import android.support.v7.widget.RecyclerView;
import android.support.v4.widget.SwipeRefreshLayout;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.NavigationView;
import android.support.design.widget.TabLayout;
import android.support.design.widget.TextInputLayout;
import android.support.design.widget.BottomNavigationView;
import android.support.design.widget.CoordinatorLayout;
import android.support.design.widget.AppBarLayout;
import android.support.design.widget.CollapsingToolbarLayout;
import android.support.v7.widget.Toolbar;
import android.support.v7.widget.CardView;
import android.support.v4.view.ViewPager;
import android.support.v4.widget.DrawerLayout;
import android.support.v4.widget.NestedScrollView;

import butterknife.ButterKnife;
import butterknife.Bind;
import butterknife.BindView;
import butterknife.OnClick;
import butterknife.InjectView;

// Security Issue: Using deprecated ButterKnife.inject API (CWE-477: Use of Obsolete Functions)

// True Positive Examples (Vulnerable/Insecure Code)

public class ButterKnifeDeprecatedExamples {

    // True Positive Examples (Vulnerable/Insecure Code)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1(Activity activity) {
        // Basic usage of deprecated ButterKnife.inject in an Activity
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, activity);
    }

    public void bad_case_2(View view) {
        // Using deprecated ButterKnife.inject with a view parameter
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, view);
    }

    public void bad_case_3(Activity activity) {
        // Using deprecated ButterKnife.inject in a fragment
        View view = activity.findViewById(android.R.id.content);
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, view);
    }

    public void bad_case_4(Activity activity) {
        // Using deprecated ButterKnife.inject with variable assignment
        boolean injected = false;
        // ruleid: java-butterknifeinjectviewdeprecated
        injected = ButterKnife.inject(this, activity);
    }

    public void bad_case_5(Activity activity) {
        // Using deprecated ButterKnife.inject in a conditional statement
        if (activity != null) {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        }
    }

    public void bad_case_6(Activity activity) {
        // Using deprecated ButterKnife.inject with a try-catch block
        try {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void bad_case_7(Activity activity) {
        // Using deprecated ButterKnife.inject with method chaining
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, activity).unbind();
    }

    public void bad_case_8(Activity activity, Object target) {
        // Using deprecated ButterKnife.inject with a different target object
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(target, activity);
    }

    public void bad_case_9(Activity activity) {
        // Using deprecated ButterKnife.inject in a loop
        for (int i = 0; i < 3; i++) {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        }
    }

    public void bad_case_10(Activity activity) {
        // Using deprecated ButterKnife.inject with a lambda expression
        Runnable r = () -> {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        };
        r.run();
    }

    public void bad_case_11(Activity activity) {
        // Using deprecated ButterKnife.inject with a switch statement
        int caseNum = 1;
        switch (caseNum) {
            case 1:
                // ruleid: java-butterknifeinjectviewdeprecated
                ButterKnife.inject(this, activity);
                break;
            default:
                break;
        }
    }

    public void bad_case_12(Activity activity) {
        // Using deprecated ButterKnife.inject with a ternary operator
        boolean condition = true;
        Object result = condition ? 
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity) : null;
    }

    public void bad_case_13(Activity activity) {
        // Using deprecated ButterKnife.inject with a custom view holder
        class ViewHolder {
            TextView textView;
        }
        ViewHolder holder = new ViewHolder();
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(holder, activity);
    }

    public void bad_case_14(Activity activity) {
        // Using deprecated ButterKnife.inject with a method reference
        Runnable r = this::injectViews;
        r.run();
    }
    
    private void injectViews(Activity activity) {
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, activity);
    }

    public void bad_case_15(Activity activity) {
        // Using deprecated ButterKnife.inject with a nested class
        class NestedClass {
            public void setup() {
                // ruleid: java-butterknifeinjectviewdeprecated
                ButterKnife.inject(this, activity);
            }
        }
        new NestedClass().setup();
    }

    // True Negative Examples (Safe/Secure Code)

    public void good_case_1(Activity activity) {
        // Using the recommended ButterKnife.bind instead of inject
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, activity);
    }

    public void good_case_2(View view) {
        // Using ButterKnife.bind with a view parameter
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, view);
    }

    public void good_case_3(Activity activity) {
        // Using ButterKnife.bind in a fragment
        View view = activity.findViewById(android.R.id.content);
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, view);
    }

    public void good_case_4(Activity activity) {
        // Using ButterKnife.bind with variable assignment
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.Unbinder unbinder = ButterKnife.bind(this, activity);
    }

    public void good_case_5(Activity activity) {
        // Using ButterKnife.bind in a conditional statement
        if (activity != null) {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        }
    }

    public void good_case_6(Activity activity) {
        // Using ButterKnife.bind with a try-catch block
        try {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void good_case_7(Activity activity, Object target) {
        // Using ButterKnife.bind with a different target object
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(target, activity);
    }

    public void good_case_8(Activity activity) {
        // Using ButterKnife.bind in a loop
        for (int i = 0; i < 3; i++) {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        }
    }

    public void good_case_9(Activity activity) {
        // Using ButterKnife.bind with a lambda expression
        Runnable r = () -> {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        };
        r.run();
    }

    public void good_case_10(Activity activity) {
        // Using ButterKnife.bind with a switch statement
        int caseNum = 1;
        switch (caseNum) {
            case 1:
                // ok: java-butterknifeinjectviewdeprecated
                ButterKnife.bind(this, activity);
                break;
            default:
                break;
        }
    }

    public void good_case_11(Activity activity) {
        // Using ButterKnife.bind with a ternary operator
        boolean condition = true;
        Object result = condition ? 
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity) : null;
    }

    public void good_case_12(Activity activity) {
        // Using ButterKnife.bind with a custom view holder
        class ViewHolder {
            @BindView(android.R.id.text1) TextView textView;
        }
        ViewHolder holder = new ViewHolder();
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(holder, activity);
    }

    public void good_case_13(Activity activity) {
        // Using ButterKnife.bind with a method reference
        Runnable r = this::bindViews;
        r.run();
    }
    
    private void bindViews(Activity activity) {
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, activity);
    }

    public void good_case_14(Activity activity) {
        // Using ButterKnife.bind with a nested class
        class NestedClass {
            public void setup() {
                // ok: java-butterknifeinjectviewdeprecated
                ButterKnife.bind(this, activity);
            }
        }
        new NestedClass().setup();
    }

    public void good_case_15() {
        // Using @BindView annotation instead of inject
        class ExampleActivity extends Activity {
            // ok: java-butterknifeinjectviewdeprecated
            @BindView(android.R.id.text1) TextView textView;
            
            @Override
            protected void onCreate(Bundle savedInstanceState) {
                super.onCreate(savedInstanceState);
                setContentView(android.R.layout.simple_list_item_1);
                ButterKnife.bind(this);
            }
        }
    }
}
// {/fact}