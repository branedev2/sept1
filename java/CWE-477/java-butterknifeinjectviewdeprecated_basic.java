import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import butterknife.ButterKnife;
import butterknife.InjectView;
import butterknife.Bind;
import butterknife.BindView;

public class ButterKnifeDeprecatedUsageExamples {

    // True Positives (vulnerable code that MUST be detected)
    
// {fact rule=deprecated-method@v1.0 defects=1}
    public void bad_case_1(Activity activity) {
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, activity);
    }
    
    public void bad_case_2(View view) {
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this, view);
    }
    
    public class BadExample1 {
        @InjectView(R.id.text_view)
        TextView textView;
        
        public void onCreate(Activity activity) {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        }
    }
    
    public class BadExample2 {
        @InjectView(R.id.button)
        Button button;
        
        public void initViews(View rootView) {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, rootView);
        }
    }
    
    public class BadExample3 extends Activity {
        @InjectView(R.id.title)
        TextView titleView;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this);
        }
    }
    
    public void bad_case_3(Activity activity) {
        MyViewHolder holder = new MyViewHolder();
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(holder, activity);
    }
    
    public void bad_case_4() {
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(this);
    }
    
    public class BadExample4 {
        @InjectView(R.id.username)
        TextView usernameField;
        
        @InjectView(R.id.password)
        TextView passwordField;
        
        public void setupViews(Activity activity) {
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, activity);
        }
    }
    
    public void bad_case_5(View view) {
        Object target = new Object();
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(target, view);
    }
    
    public class BadExample5 extends Fragment {
        @InjectView(R.id.submit_button)
        Button submitButton;
        
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.fragment_layout, container, false);
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, view);
            return view;
        }
    }
    
    public void bad_case_6(Activity activity) {
        for (int i = 0; i < 5; i++) {
            MyCustomView customView = new MyCustomView();
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(customView, activity);
        }
    }
    
    public class BadExample6 {
        @InjectView(R.id.recycler_view)
        RecyclerView recyclerView;
        
        public void initializeViews(Activity activity) {
            if (activity != null) {
                // ruleid: java-butterknifeinjectviewdeprecated
                ButterKnife.inject(this, activity);
            }
        }
    }
    
    public void bad_case_7(View dialogView) {
        DialogViewHolder holder = new DialogViewHolder();
        // ruleid: java-butterknifeinjectviewdeprecated
        ButterKnife.inject(holder, dialogView);
        holder.setupDialog();
    }
    
    public class BadExample7 extends DialogFragment {
        @InjectView(R.id.dialog_title)
        TextView dialogTitle;
        
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.dialog_layout, container, false);
            // ruleid: java-butterknifeinjectviewdeprecated
            ButterKnife.inject(this, view);
            return view;
        }
    }
    
    // True Negatives (safe code that MUST NOT be detected)
    
    public void good_case_1(Activity activity) {
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, activity);
    }
    
    public void good_case_2(View view) {
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this, view);
    }
    
    public class GoodExample1 {
        @BindView(R.id.text_view)
        TextView textView;
        
        public void onCreate(Activity activity) {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        }
    }
    
    public class GoodExample2 {
        @BindView(R.id.button)
        Button button;
        
        public void initViews(View rootView) {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, rootView);
        }
    }
    
    public class GoodExample3 extends Activity {
        @BindView(R.id.title)
        TextView titleView;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this);
        }
    }
    
    public void good_case_3(Activity activity) {
        MyViewHolder holder = new MyViewHolder();
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(holder, activity);
    }
    
    public void good_case_4() {
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(this);
    }
    
    public class GoodExample4 {
        @BindView(R.id.username)
        TextView usernameField;
        
        @BindView(R.id.password)
        TextView passwordField;
        
        public void setupViews(Activity activity) {
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, activity);
        }
    }
    
    public void good_case_5(View view) {
        Object target = new Object();
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(target, view);
    }
    
    public class GoodExample5 extends Fragment {
        @BindView(R.id.submit_button)
        Button submitButton;
        
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.fragment_layout, container, false);
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, view);
            return view;
        }
    }
    
    public void good_case_6(Activity activity) {
        for (int i = 0; i < 5; i++) {
            MyCustomView customView = new MyCustomView();
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(customView, activity);
        }
    }
    
    public class GoodExample6 {
        @BindView(R.id.recycler_view)
        RecyclerView recyclerView;
        
        public void initializeViews(Activity activity) {
            if (activity != null) {
                // ok: java-butterknifeinjectviewdeprecated
                ButterKnife.bind(this, activity);
            }
        }
    }
    
    public void good_case_7(View dialogView) {
        DialogViewHolder holder = new DialogViewHolder();
        // ok: java-butterknifeinjectviewdeprecated
        ButterKnife.bind(holder, dialogView);
        holder.setupDialog();
    }
    
    public class GoodExample7 extends DialogFragment {
        @BindView(R.id.dialog_title)
        TextView dialogTitle;
        
        @Override
        public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
            View view = inflater.inflate(R.layout.dialog_layout, container, false);
            // ok: java-butterknifeinjectviewdeprecated
            ButterKnife.bind(this, view);
            return view;
        }
    }
    
    // Alternative view binding approach without ButterKnife
    public class GoodExample8 extends Activity {
        private TextView titleView;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            // ok: java-butterknifeinjectviewdeprecated
            titleView = findViewById(R.id.title);
        }
    }
    
    // Using ViewBinding (Android's newer recommended approach)
    public class GoodExample9 extends Activity {
        private ActivityMainBinding binding;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            // ok: java-butterknifeinjectviewdeprecated
            binding = ActivityMainBinding.inflate(getLayoutInflater());
            setContentView(binding.getRoot());
        }
    }
    
    // Using DataBinding
    public class GoodExample10 extends Activity {
        private ActivityMainBinding binding;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            // ok: java-butterknifeinjectviewdeprecated
            binding = DataBindingUtil.setContentView(this, R.layout.activity_main);
        }
    }
    
    // Using Kotlin synthetic properties (in Java-compatible way)
    public class GoodExample11 extends Activity {
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            // ok: java-butterknifeinjectviewdeprecated
            TextView titleView = findViewById(R.id.title);
            Button submitButton = findViewById(R.id.submit_button);
        }
    }
    
    // Using Dagger for dependency injection instead of ButterKnife
    public class GoodExample12 extends Activity {
        @Inject
        SomePresenter presenter;
        
        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_main);
            // ok: java-butterknifeinjectviewdeprecated
            ((MyApplication) getApplication()).getAppComponent().inject(this);
        }
    }
}
// {/fact}