import * as Docker from 'dockerode';
import * as express from 'express';
import * as http from 'http';
import * as url from 'url';
import * as fs from 'fs';
import { sanitizeInput, validateContainerName } from './security-utils';

// Initialize Docker client
const docker = new Docker();
const app = express();
app.use(express.json());

// BAD EXAMPLES - Vulnerable code

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_1() {
    app.get('/run-container', (req, res) => {
        const containerName = req.query.name as string;
        
        // ruleid: typescript-tainted-input-for-docker-api
        docker.createContainer({
            Image: 'nginx',
            name: containerName,
            Cmd: ['/bin/bash']
        }, (err, container) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            container.start((err) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.send(`Container ${containerName} started`);
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_2() {
    app.post('/execute-command', (req, res) => {
        const containerId = req.body.containerId;
        const command = req.body.command;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.exec({
            Cmd: ['sh', '-c', command],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            exec.start({}, (err, stream) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.send('Command executed');
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_3() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        if (parsedUrl.pathname === '/pull-image') {
            const imageName = parsedUrl.query.image as string;
            
            // ruleid: typescript-tainted-input-for-docker-api
            docker.pull(imageName, (err, stream) => {
                if (err) {
                    res.writeHead(500);
                    res.end(JSON.stringify(err));
                    return;
                }
                
                docker.modem.followProgress(stream, (err, output) => {
                    res.writeHead(200, {'Content-Type': 'application/json'});
                    res.end(JSON.stringify({success: true, output}));
                });
            });
        }
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_4() {
    app.get('/container-logs', (req, res) => {
        const containerId = req.query.id as string;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.logs({
            follow: true,
            stdout: true,
            stderr: true
        }, (err, stream) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            stream.pipe(res);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_5() {
    app.post('/create-volume', (req, res) => {
        const volumeName = req.body.name;
        const driver = req.body.driver;
        
        // ruleid: typescript-tainted-input-for-docker-api
        docker.createVolume({
            Name: volumeName,
            Driver: driver
        }, (err, volume) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(volume);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_6() {
    app.get('/network-connect', (req, res) => {
        const networkId = req.query.network as string;
        const containerId = req.query.container as string;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const network = docker.getNetwork(networkId);
        network.connect({
            Container: containerId
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Container connected to network');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_7() {
    app.post('/build-image', (req, res) => {
        const tag = req.body.tag;
        const dockerfile = req.body.dockerfile;
        
        fs.writeFileSync('./Dockerfile.temp', dockerfile);
        
        // ruleid: typescript-tainted-input-for-docker-api
        docker.buildImage({
            context: process.cwd(),
            src: ['Dockerfile.temp']
        }, {
            t: tag
        }, (err, stream) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            docker.modem.followProgress(stream, (err, output) => {
                fs.unlinkSync('./Dockerfile.temp');
                res.json(output);
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_8() {
    app.delete('/remove-container', (req, res) => {
        const containerId = req.query.id as string;
        const force = req.query.force === 'true';
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.remove({
            force: force
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send(`Container ${containerId} removed`);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_9() {
    app.post('/exec-resize', (req, res) => {
        const execId = req.body.execId;
        const height = parseInt(req.body.height);
        const width = parseInt(req.body.width);
        
        // ruleid: typescript-tainted-input-for-docker-api
        const exec = docker.getExec(execId);
        exec.resize({
            h: height,
            w: width
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Exec resized');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_10() {
    app.get('/container-stats', (req, res) => {
        const containerId = req.query.id as string;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.stats({
            stream: false
        }, (err, stats) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(stats);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_11() {
    app.post('/container-rename', (req, res) => {
        const containerId = req.body.id;
        const newName = req.body.name;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.rename({
            name: newName
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send(`Container renamed to ${newName}`);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_12() {
    app.post('/network-create', (req, res) => {
        const networkName = req.body.name;
        
        // ruleid: typescript-tainted-input-for-docker-api
        docker.createNetwork({
            Name: networkName,
            Driver: 'bridge'
        }, (err, network) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(network);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_13() {
    app.get('/container-inspect', (req, res) => {
        const containerId = req.query.id as string;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.inspect((err, data) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(data);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_14() {
    app.post('/container-update', (req, res) => {
        const containerId = req.body.id;
        const cpuShares = parseInt(req.body.cpuShares);
        const memory = parseInt(req.body.memory);
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.update({
            CpuShares: cpuShares,
            Memory: memory
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Container updated');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_15() {
    app.post('/container-wait', (req, res) => {
        const containerId = req.body.id;
        
        // ruleid: typescript-tainted-input-for-docker-api
        const container = docker.getContainer(containerId);
        container.wait((err, data) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(data);
        });
    });
}
// {/fact}

// GOOD EXAMPLES - Secure code

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_1() {
    app.get('/run-container', (req, res) => {
        const containerName = req.query.name as string;
        
        // Validate container name format
        // ok: typescript-tainted-input-for-docker-api
        if (!validateContainerName(containerName)) {
            res.status(400).send('Invalid container name');
            return;
        }
        
        docker.createContainer({
            Image: 'nginx',
            name: containerName,
            Cmd: ['/bin/bash']
        }, (err, container) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            container.start((err) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.send(`Container ${containerName} started`);
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_2() {
    app.post('/execute-command', (req, res) => {
        const containerId = req.body.containerId;
        
        // Use predefined commands instead of user input
        // ok: typescript-tainted-input-for-docker-api
        const allowedCommands = {
            'list': 'ls -la',
            'disk': 'df -h',
            'memory': 'free -m'
        };
        
        const commandKey = req.body.commandKey;
        const command = allowedCommands[commandKey];
        
        if (!command) {
            res.status(400).send('Invalid command key');
            return;
        }
        
        const container = docker.getContainer(containerId);
        container.exec({
            Cmd: ['sh', '-c', command],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            exec.start({}, (err, stream) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.send('Command executed');
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_3() {
    const server = http.createServer((req, res) => {
        const parsedUrl = url.parse(req.url || '', true);
        if (parsedUrl.pathname === '/pull-image') {
            const imageName = parsedUrl.query.image as string;
            
            // Whitelist of allowed images
            // ok: typescript-tainted-input-for-docker-api
            const allowedImages = [
                'nginx:latest',
                'node:14',
                'postgres:13',
                'redis:alpine'
            ];
            
            if (!allowedImages.includes(imageName)) {
                res.writeHead(400);
                res.end('Image not allowed');
                return;
            }
            
            docker.pull(imageName, (err, stream) => {
                if (err) {
                    res.writeHead(500);
                    res.end(JSON.stringify(err));
                    return;
                }
                
                docker.modem.followProgress(stream, (err, output) => {
                    res.writeHead(200, {'Content-Type': 'application/json'});
                    res.end(JSON.stringify({success: true, output}));
                });
            });
        }
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_4() {
    app.get('/container-logs', (req, res) => {
        const containerId = req.query.id as string;
        
        // Validate container ID format (hex string)
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid container ID format');
            return;
        }
        
        const container = docker.getContainer(containerId);
        container.logs({
            follow: true,
            stdout: true,
            stderr: true
        }, (err, stream) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            stream.pipe(res);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_5() {
    app.post('/create-volume', (req, res) => {
        const volumeName = req.body.name;
        
        // Sanitize volume name
        // ok: typescript-tainted-input-for-docker-api
        const sanitizedName = sanitizeInput(volumeName);
        if (sanitizedName !== volumeName) {
            res.status(400).send('Invalid volume name');
            return;
        }
        
        // Use only allowed drivers
        const allowedDrivers = ['local', 'nfs'];
        const driver = allowedDrivers.includes(req.body.driver) ? req.body.driver : 'local';
        
        docker.createVolume({
            Name: sanitizedName,
            Driver: driver
        }, (err, volume) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(volume);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_6() {
    app.get('/network-connect', (req, res) => {
        // Use UUID validation for network and container IDs
        // ok: typescript-tainted-input-for-docker-api
        const networkId = req.query.network as string;
        const containerId = req.query.container as string;
        
        if (!/^[a-f0-9]{64}$/.test(networkId) || !/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid ID format');
            return;
        }
        
        const network = docker.getNetwork(networkId);
        network.connect({
            Container: containerId
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Container connected to network');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_7() {
    app.post('/build-image', (req, res) => {
        // Use predefined Dockerfiles instead of user input
        // ok: typescript-tainted-input-for-docker-api
        const dockerfileTemplates = {
            'node': 'FROM node:14\nWORKDIR /app\nCOPY . .\nRUN npm install\nCMD ["npm", "start"]',
            'python': 'FROM python:3.9\nWORKDIR /app\nCOPY . .\nRUN pip install -r requirements.txt\nCMD ["python", "app.py"]'
        };
        
        const templateKey = req.body.template;
        const dockerfile = dockerfileTemplates[templateKey];
        
        if (!dockerfile) {
            res.status(400).send('Invalid template');
            return;
        }
        
        // Validate tag format
        const tag = req.body.tag;
        if (!/^[a-z0-9][a-z0-9_.-]+:[a-z0-9_.-]+$/.test(tag)) {
            res.status(400).send('Invalid tag format');
            return;
        }
        
        fs.writeFileSync('./Dockerfile.temp', dockerfile);
        
        docker.buildImage({
            context: process.cwd(),
            src: ['Dockerfile.temp']
        }, {
            t: tag
        }, (err, stream) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            docker.modem.followProgress(stream, (err, output) => {
                fs.unlinkSync('./Dockerfile.temp');
                res.json(output);
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_8() {
    app.delete('/remove-container', (req, res) => {
        const containerId = req.query.id as string;
        
        // Validate container ID and force parameter
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid container ID format');
            return;
        }
        
        // Convert string to boolean safely
        const force = req.query.force === 'true';
        
        const container = docker.getContainer(containerId);
        container.remove({
            force: force
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send(`Container ${containerId} removed`);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_9() {
    app.post('/exec-resize', (req, res) => {
        const execId = req.body.execId;
        
        // Validate exec ID and dimensions
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-f0-9]{64}$/.test(execId)) {
            res.status(400).send('Invalid exec ID format');
            return;
        }
        
        // Validate and limit dimensions
        const height = Math.min(Math.max(parseInt(req.body.height) || 24, 10), 100);
        const width = Math.min(Math.max(parseInt(req.body.width) || 80, 10), 200);
        
        const exec = docker.getExec(execId);
        exec.resize({
            h: height,
            w: width
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Exec resized');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_10() {
    app.get('/container-stats', (req, res) => {
        // Use a container lookup service instead of direct user input
        // ok: typescript-tainted-input-for-docker-api
        const containerName = req.query.name as string;
        
        // Validate container name
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(containerName)) {
            res.status(400).send('Invalid container name format');
            return;
        }
        
        // Get container ID from name using Docker API
        docker.listContainers((err, containers) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            const container = containers.find(c => 
                c.Names.some(name => name === `/${containerName}` || name === containerName)
            );
            
            if (!container) {
                res.status(404).send('Container not found');
                return;
            }
            
            const containerObj = docker.getContainer(container.Id);
            containerObj.stats({
                stream: false
            }, (err, stats) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.json(stats);
            });
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_11() {
    app.post('/container-rename', (req, res) => {
        const containerId = req.body.id;
        const newName = req.body.name;
        
        // Validate container ID and new name
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid container ID format');
            return;
        }
        
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(newName)) {
            res.status(400).send('Invalid container name format');
            return;
        }
        
        const container = docker.getContainer(containerId);
        container.rename({
            name: newName
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send(`Container renamed to ${newName}`);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_12() {
    app.post('/network-create', (req, res) => {
        const networkName = req.body.name;
        
        // Validate network name
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(networkName)) {
            res.status(400).send('Invalid network name format');
            return;
        }
        
        // Use only allowed drivers
        const allowedDrivers = ['bridge', 'overlay', 'macvlan'];
        const requestedDriver = req.body.driver;
        const driver = allowedDrivers.includes(requestedDriver) ? requestedDriver : 'bridge';
        
        docker.createNetwork({
            Name: networkName,
            Driver: driver
        }, (err, network) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(network);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_13() {
    app.get('/container-inspect', (req, res) => {
        // Use authentication and authorization before allowing access
        // ok: typescript-tainted-input-for-docker-api
        const containerId = req.query.id as string;
        const userRole = req.headers['x-user-role'];
        
        // Check user permissions
        if (userRole !== 'admin' && userRole !== 'operator') {
            res.status(403).send('Unauthorized');
            return;
        }
        
        // Validate container ID
        if (!/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid container ID format');
            return;
        }
        
        const container = docker.getContainer(containerId);
        container.inspect((err, data) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.json(data);
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_14() {
    app.post('/container-update', (req, res) => {
        const containerId = req.body.id;
        
        // Validate container ID and resource limits
        // ok: typescript-tainted-input-for-docker-api
        if (!/^[a-f0-9]{64}$/.test(containerId)) {
            res.status(400).send('Invalid container ID format');
            return;
        }
        
        // Validate and limit resource values
        const cpuShares = Math.min(Math.max(parseInt(req.body.cpuShares) || 512, 2), 1024);
        const memory = Math.min(Math.max(parseInt(req.body.memory) || 256 * 1024 * 1024, 4 * 1024 * 1024), 4 * 1024 * 1024 * 1024);
        
        const container = docker.getContainer(containerId);
        container.update({
            CpuShares: cpuShares,
            Memory: memory
        }, (err) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            res.send('Container updated');
        });
    });
}
// {/fact}

// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_15() {
    app.post('/container-wait', (req, res) => {
        // Use a container lookup service with validation
        // ok: typescript-tainted-input-for-docker-api
        const containerName = req.body.name;
        
        // Validate container name
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(containerName)) {
            res.status(400).send('Invalid container name format');
            return;
        }
        
        // Get container ID from name using Docker API
        docker.listContainers((err, containers) => {
            if (err) {
                res.status(500).send(err);
                return;
            }
            
            const container = containers.find(c => 
                c.Names.some(name => name === `/${containerName}` || name === containerName)
            );
            
            if (!container) {
                res.status(404).send('Container not found');
                return;
            }
            
            const containerObj = docker.getContainer(container.Id);
            containerObj.wait((err, data) => {
                if (err) {
                    res.status(500).send(err);
                    return;
                }
                res.json(data);
            });
        });
    });
}
// {/fact}

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});