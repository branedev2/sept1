import React from 'react';
import styled from 'styled-components';

// TRUE POSITIVES (BAD CASES) - Styled components defined inside render methods

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_1() {
  // Component with styled component defined inside render
  class Button extends React.Component {
    render() {
      // ruleid: javascript-react-styled-components
      const StyledButton = styled.button`
        background-color: blue;
        color: white;
        padding: 10px 15px;
        border-radius: 4px;
      `;
      
      return <StyledButton>{this.props.children}</StyledButton>;
    }
  }
  
  return <Button>Click Me</Button>;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_2() {
  // Functional component with styled component inside render
  const Header = (props) => {
    // ruleid: javascript-react-styled-components
    const HeaderContainer = styled.header`
      background-color: #333;
      color: white;
      padding: 20px;
    `;
    
    return <HeaderContainer>{props.title}</HeaderContainer>;
  };
  
  return <Header title="My Application" />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_3() {
  // Styled component inside conditional rendering
  const ConditionalComponent = ({ isAdmin }) => {
    if (isAdmin) {
      // ruleid: javascript-react-styled-components
      const AdminPanel = styled.div`
        background-color: #f8f9fa;
        border: 1px solid red;
        padding: 15px;
      `;
      
      return <AdminPanel>Admin Controls</AdminPanel>;
    }
    
    return <div>Regular User View</div>;
  };
  
  return <ConditionalComponent isAdmin={true} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_4() {
  // Styled component inside useEffect hook
  const DynamicComponent = () => {
    const [isLoaded, setIsLoaded] = React.useState(false);
    
    React.useEffect(() => {
      if (isLoaded) {
        // ruleid: javascript-react-styled-components
        const LoadedContent = styled.div`
          animation: fadeIn 0.5s ease-in;
          padding: 10px;
        `;
        
        return <LoadedContent>Content has loaded!</LoadedContent>;
      }
    }, [isLoaded]);
    
    return <div>Loading...</div>;
  };
  
  return <DynamicComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_5() {
  // Styled component inside map function
  const ItemList = ({ items }) => {
    return (
      <div>
        {items.map((item, index) => {
          // ruleid: javascript-react-styled-components
          const ListItem = styled.li`
            margin-bottom: 10px;
            padding: 8px;
            background-color: ${index % 2 === 0 ? '#f0f0f0' : 'white'};
          `;
          
          return <ListItem key={index}>{item.name}</ListItem>;
        })}
      </div>
    );
  };
  
  return <ItemList items={[{name: 'Item 1'}, {name: 'Item 2'}]} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_6() {
  // Styled component inside event handler
  const ClickableArea = () => {
    const handleClick = () => {
      // ruleid: javascript-react-styled-components
      const Notification = styled.div`
        position: absolute;
        top: 20px;
        right: 20px;
        background-color: green;
        color: white;
        padding: 10px;
      `;
      
      return <Notification>Clicked!</Notification>;
    };
    
    return <div onClick={handleClick}>Click me</div>;
  };
  
  return <ClickableArea />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_7() {
  // Styled component inside render prop
  const RenderPropComponent = ({ render }) => {
    return render();
  };
  
  return (
    <RenderPropComponent 
      render={() => {
        // ruleid: javascript-react-styled-components
        const StyledContent = styled.section`
          margin: 20px;
          padding: 15px;
          border: 1px solid #ddd;
        `;
        
        return <StyledContent>Rendered content</StyledContent>;
      }} 
    />
  );
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_8() {
  // Styled component inside useState initialization
  const StateComponent = () => {
    // ruleid: javascript-react-styled-components
    const [StyledElement] = React.useState(() => styled.div`
      font-weight: bold;
      color: purple;
    `);
    
    return <StyledElement>Styled with useState</StyledElement>;
  };
  
  return <StateComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_9() {
  // Styled component inside useMemo
  const MemoComponent = ({ theme }) => {
    const ThemedButton = React.useMemo(() => {
      // ruleid: javascript-react-styled-components
      return styled.button`
        background-color: ${theme === 'dark' ? '#333' : '#f0f0f0'};
        color: ${theme === 'dark' ? 'white' : 'black'};
        padding: 10px;
      `;
    }, [theme]);
    
    return <ThemedButton>Themed Button</ThemedButton>;
  };
  
  return <MemoComponent theme="dark" />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_10() {
  // Styled component inside callback function
  const CallbackComponent = () => {
    const handleCallback = (callback) => {
      // ruleid: javascript-react-styled-components
      const CallbackResult = styled.div`
        border: 2px dashed blue;
        padding: 10px;
        margin-top: 20px;
      `;
      
      return <CallbackResult>{callback()}</CallbackResult>;
    };
    
    return handleCallback(() => "Callback executed");
  };
  
  return <CallbackComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_11() {
  // Styled component inside switch statement
  const SwitchComponent = ({ status }) => {
    let StatusDisplay;
    
    switch (status) {
      case 'success':
        // ruleid: javascript-react-styled-components
        StatusDisplay = styled.div`
          color: green;
          font-weight: bold;
        `;
        break;
      case 'error':
        // ruleid: javascript-react-styled-components
        StatusDisplay = styled.div`
          color: red;
          font-weight: bold;
        `;
        break;
      default:
        // ruleid: javascript-react-styled-components
        StatusDisplay = styled.div`
          color: gray;
        `;
    }
    
    return <StatusDisplay>Status: {status}</StatusDisplay>;
  };
  
  return <SwitchComponent status="success" />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_12() {
  // Styled component inside nested function
  const NestedComponent = () => {
    const createNestedElement = () => {
      const createStyledElement = () => {
        // ruleid: javascript-react-styled-components
        const NestedStyledElement = styled.div`
          border: 1px solid #ccc;
          padding: 8px;
          margin: 5px;
        `;
        
        return <NestedStyledElement>Deeply nested</NestedStyledElement>;
      };
      
      return createStyledElement();
    };
    
    return createNestedElement();
  };
  
  return <NestedComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_13() {
  // Styled component inside render with props
  const DynamicStyledComponent = ({ color, size }) => {
    // ruleid: javascript-react-styled-components
    const DynamicBox = styled.div`
      background-color: ${color};
      width: ${size}px;
      height: ${size}px;
    `;
    
    return <DynamicBox />;
  };
  
  return <DynamicStyledComponent color="blue" size={100} />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_14() {
  // Styled component inside async function
  const AsyncComponent = () => {
    const [data, setData] = React.useState(null);
    
    React.useEffect(() => {
      const fetchData = async () => {
        // Simulate API call
        const result = await new Promise(resolve => 
          setTimeout(() => resolve({ title: "Async Data" }), 1000)
        );
        
        // ruleid: javascript-react-styled-components
        const AsyncResult = styled.div`
          border: 1px solid green;
          padding: 15px;
          margin-top: 10px;
        `;
        
        setData(<AsyncResult>{result.title}</AsyncResult>);
      };
      
      fetchData();
    }, []);
    
    return <div>{data || "Loading..."}</div>;
  };
  
  return <AsyncComponent />;
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
function bad_case_15() {
  // Styled component inside render with dynamic theme
  const ThemeConsumer = () => {
    const theme = { primary: 'blue', secondary: 'gray' };
    
    return (
      <div>
        {(() => {
          // ruleid: javascript-react-styled-components
          const ThemedHeader = styled.h1`
            color: ${theme.primary};
            border-bottom: 2px solid ${theme.secondary};
            padding-bottom: 10px;
          `;
          
          return <ThemedHeader>Themed Header</ThemedHeader>;
        })()}
      </div>
    );
  };
  
  return <ThemeConsumer />;
}
// {/fact}

// TRUE NEGATIVES (GOOD CASES) - Styled components defined at module level

// ok: javascript-react-styled-components
const StyledButton = styled.button`
  background-color: blue;
  color: white;
  padding: 10px 15px;
  border-radius: 4px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_1() {
  // Using styled component defined at module level
  class Button extends React.Component {
    render() {
      return <StyledButton>{this.props.children}</StyledButton>;
    }
  }
  
  return <Button>Click Me</Button>;
}
// {/fact}

// ok: javascript-react-styled-components
const HeaderContainer = styled.header`
  background-color: #333;
  color: white;
  padding: 20px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_2() {
  // Functional component using module-level styled component
  const Header = (props) => {
    return <HeaderContainer>{props.title}</HeaderContainer>;
  };
  
  return <Header title="My Application" />;
}
// {/fact}

// ok: javascript-react-styled-components
const AdminPanel = styled.div`
  background-color: #f8f9fa;
  border: 1px solid red;
  padding: 15px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_3() {
  // Conditional rendering with module-level styled component
  const ConditionalComponent = ({ isAdmin }) => {
    if (isAdmin) {
      return <AdminPanel>Admin Controls</AdminPanel>;
    }
    
    return <div>Regular User View</div>;
  };
  
  return <ConditionalComponent isAdmin={true} />;
}
// {/fact}

// ok: javascript-react-styled-components
const LoadedContent = styled.div`
  animation: fadeIn 0.5s ease-in;
  padding: 10px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_4() {
  // Using styled component in useEffect
  const DynamicComponent = () => {
    const [isLoaded, setIsLoaded] = React.useState(false);
    
    React.useEffect(() => {
      if (isLoaded) {
        return <LoadedContent>Content has loaded!</LoadedContent>;
      }
    }, [isLoaded]);
    
    return <div>Loading...</div>;
  };
  
  return <DynamicComponent />;
}
// {/fact}

// ok: javascript-react-styled-components
const ListItem = styled.li`
  margin-bottom: 10px;
  padding: 8px;
  background-color: ${props => props.isEven ? '#f0f0f0' : 'white'};
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_5() {
  // Using styled component with props in map function
  const ItemList = ({ items }) => {
    return (
      <div>
        {items.map((item, index) => (
          <ListItem key={index} isEven={index % 2 === 0}>
            {item.name}
          </ListItem>
        ))}
      </div>
    );
  };
  
  return <ItemList items={[{name: 'Item 1'}, {name: 'Item 2'}]} />;
}
// {/fact}

// ok: javascript-react-styled-components
const Notification = styled.div`
  position: absolute;
  top: 20px;
  right: 20px;
  background-color: green;
  color: white;
  padding: 10px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_6() {
  // Using styled component in event handler
  const ClickableArea = () => {
    const handleClick = () => {
      return <Notification>Clicked!</Notification>;
    };
    
    return <div onClick={handleClick}>Click me</div>;
  };
  
  return <ClickableArea />;
}
// {/fact}

// ok: javascript-react-styled-components
const StyledContent = styled.section`
  margin: 20px;
  padding: 15px;
  border: 1px solid #ddd;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_7() {
  // Using styled component in render prop
  const RenderPropComponent = ({ render }) => {
    return render();
  };
  
  return (
    <RenderPropComponent 
      render={() => <StyledContent>Rendered content</StyledContent>} 
    />
  );
}
// {/fact}

// ok: javascript-react-styled-components
const BoldPurpleText = styled.div`
  font-weight: bold;
  color: purple;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_8() {
  // Using module-level styled component with useState
  const StateComponent = () => {
    const [showElement, setShowElement] = React.useState(true);
    
    return showElement ? <BoldPurpleText>Styled with useState</BoldPurpleText> : null;
  };
  
  return <StateComponent />;
}
// {/fact}

// ok: javascript-react-styled-components
const DarkButton = styled.button`
  background-color: #333;
  color: white;
  padding: 10px;
`;

// ok: javascript-react-styled-components
const LightButton = styled.button`
  background-color: #f0f0f0;
  color: black;
  padding: 10px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_9() {
  // Using different styled components based on theme
  const MemoComponent = ({ theme }) => {
    const ThemedButton = theme === 'dark' ? DarkButton : LightButton;
    
    return <ThemedButton>Themed Button</ThemedButton>;
  };
  
  return <MemoComponent theme="dark" />;
}
// {/fact}

// ok: javascript-react-styled-components
const CallbackResult = styled.div`
  border: 2px dashed blue;
  padding: 10px;
  margin-top: 20px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_10() {
  // Using styled component in callback function
  const CallbackComponent = () => {
    const handleCallback = (callback) => {
      return <CallbackResult>{callback()}</CallbackResult>;
    };
    
    return handleCallback(() => "Callback executed");
  };
  
  return <CallbackComponent />;
}
// {/fact}

// ok: javascript-react-styled-components
const SuccessStatus = styled.div`
  color: green;
  font-weight: bold;
`;

// ok: javascript-react-styled-components
const ErrorStatus = styled.div`
  color: red;
  font-weight: bold;
`;

// ok: javascript-react-styled-components
const DefaultStatus = styled.div`
  color: gray;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_11() {
  // Using styled components with switch statement
  const SwitchComponent = ({ status }) => {
    let StatusDisplay;
    
    switch (status) {
      case 'success':
        StatusDisplay = SuccessStatus;
        break;
      case 'error':
        StatusDisplay = ErrorStatus;
        break;
      default:
        StatusDisplay = DefaultStatus;
    }
    
    return <StatusDisplay>Status: {status}</StatusDisplay>;
  };
  
  return <SwitchComponent status="success" />;
}
// {/fact}

// ok: javascript-react-styled-components
const NestedStyledElement = styled.div`
  border: 1px solid #ccc;
  padding: 8px;
  margin: 5px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_12() {
  // Using styled component in nested function
  const NestedComponent = () => {
    const createNestedElement = () => {
      const createStyledElement = () => {
        return <NestedStyledElement>Deeply nested</NestedStyledElement>;
      };
      
      return createStyledElement();
    };
    
    return createNestedElement();
  };
  
  return <NestedComponent />;
}
// {/fact}

// ok: javascript-react-styled-components
const DynamicBox = styled.div`
  background-color: ${props => props.color};
  width: ${props => props.size}px;
  height: ${props => props.size}px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_13() {
  // Using styled component with props
  const DynamicStyledComponent = ({ color, size }) => {
    return <DynamicBox color={color} size={size} />;
  };
  
  return <DynamicStyledComponent color="blue" size={100} />;
}
// {/fact}

// ok: javascript-react-styled-components
const AsyncResult = styled.div`
  border: 1px solid green;
  padding: 15px;
  margin-top: 10px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_14() {
  // Using styled component in async function
  const AsyncComponent = () => {
    const [data, setData] = React.useState(null);
    
    React.useEffect(() => {
      const fetchData = async () => {
        // Simulate API call
        const result = await new Promise(resolve => 
          setTimeout(() => resolve({ title: "Async Data" }), 1000)
        );
        
        setData(<AsyncResult>{result.title}</AsyncResult>);
      };
      
      fetchData();
    }, []);
    
    return <div>{data || "Loading..."}</div>;
  };
  
  return <AsyncComponent />;
}
// {/fact}

// ok: javascript-react-styled-components
const ThemedHeader = styled.h1`
  color: ${props => props.theme.primary};
  border-bottom: 2px solid ${props => props.theme.secondary};
  padding-bottom: 10px;
`;

// {fact rule=guru-cfn-lint@v1.0 defects=0}
function good_case_15() {
  // Using styled component with theme props
  const ThemeConsumer = () => {
    const theme = { primary: 'blue', secondary: 'gray' };
    
    return (
      <div>
        <ThemedHeader theme={theme}>Themed Header</ThemedHeader>
      </div>
    );
  };
  
  return <ThemeConsumer />;
}
// {/fact}