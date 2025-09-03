const express = require('express');
const Docker = require('dockerode');
const sanitize = require('sanitize-html');
const { execSync } = require('child_process');
const app = express();
const docker = new Docker();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// True Positive Examples (Vulnerable Code)

// Bad case 1: Using user input directly in container creation
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_1() {
    app.post('/create-container', (req, res) => {
        const containerName = req.body.name;
        const imageTag = req.body.tag;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.createContainer({
            Image: `${imageTag}`,
            name: containerName,
            Cmd: ['/bin/bash']
        }, (err, container) => {
            if (err) {
                return res.status(500).send(err);
            }
            res.send(`Container created: ${container.id}`);
        });
    });
}
// {/fact}

// Bad case 2: Using query parameters in Docker exec
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_2() {
    app.get('/exec-command', (req, res) => {
        const containerId = req.query.container;
        const command = req.query.cmd;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).exec({
            Cmd: ['sh', '-c', command],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) return res.status(500).send(err);
            res.send('Command executed');
        });
    });
}
// {/fact}

// Bad case 3: Using headers in Docker API calls
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_3() {
    app.get('/container-logs', (req, res) => {
        const containerId = req.headers['x-container-id'];
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).logs({
            follow: true,
            stdout: true,
            stderr: true
        }, (err, stream) => {
            if (err) return res.status(500).send(err);
            stream.pipe(res);
        });
    });
}
// {/fact}

// Bad case 4: Using cookies in Docker API
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_4() {
    app.get('/container-stats', (req, res) => {
        const containerId = req.cookies.containerId;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).stats({
            stream: false
        }, (err, stats) => {
            if (err) return res.status(500).send(err);
            res.json(stats);
        });
    });
}
// {/fact}

// Bad case 5: Using user input in Docker build context
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_5() {
    app.post('/build-image', (req, res) => {
        const tag = req.body.tag;
        const dockerfilePath = req.body.path;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.buildImage({
            context: dockerfilePath,
            src: ['Dockerfile']
        }, {
            t: tag
        }, (err, stream) => {
            if (err) return res.status(500).send(err);
            res.send('Building image...');
        });
    });
}
// {/fact}

// Bad case 6: Using URL parameters in Docker volume creation
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_6() {
    app.get('/create-volume/:name', (req, res) => {
        const volumeName = req.params.name;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.createVolume({
            Name: volumeName,
            Driver: 'local'
        }, (err, volume) => {
            if (err) return res.status(500).send(err);
            res.json(volume);
        });
    });
}
// {/fact}

// Bad case 7: Using form data in Docker network creation
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_7() {
    app.post('/create-network', (req, res) => {
        const networkName = req.body.name;
        const driver = req.body.driver;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.createNetwork({
            Name: networkName,
            Driver: driver
        }, (err, network) => {
            if (err) return res.status(500).send(err);
            res.json(network);
        });
    });
}
// {/fact}

// Bad case 8: Using query parameters in Docker run command
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_8() {
    app.get('/run-container', (req, res) => {
        const image = req.query.image;
        const cmd = req.query.cmd;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.run(image, ['sh', '-c', cmd], process.stdout, (err, data) => {
            if (err) return res.status(500).send(err);
            res.send(`Container exited with code ${data.StatusCode}`);
        });
    });
}
// {/fact}

// Bad case 9: Using request body in Docker container removal
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_9() {
    app.delete('/remove-container', (req, res) => {
        const containerId = req.body.id;
        const force = req.body.force === 'true';
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).remove({
            force: force
        }, (err) => {
            if (err) return res.status(500).send(err);
            res.send('Container removed');
        });
    });
}
// {/fact}

// Bad case 10: Using user input in Docker image pull
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_10() {
    app.post('/pull-image', (req, res) => {
        const imageName = req.body.image;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.pull(imageName, (err, stream) => {
            if (err) return res.status(500).send(err);
            docker.modem.followProgress(stream, (err, output) => {
                if (err) return res.status(500).send(err);
                res.send('Image pulled successfully');
            });
        });
    });
}
// {/fact}

// Bad case 11: Using user input in Docker exec with direct shell command
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_11() {
    app.post('/exec-shell', (req, res) => {
        const containerId = req.body.container;
        const shellCommand = req.body.command;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).exec({
            Cmd: ['/bin/sh', '-c', shellCommand],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) return res.status(500).send(err);
            exec.start({}, (err, stream) => {
                if (err) return res.status(500).send(err);
                res.send('Command executed');
            });
        });
    });
}
// {/fact}

// Bad case 12: Using user input in Docker CLI via child_process
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_12() {
    app.post('/docker-cli', (req, res) => {
        const command = req.body.command;
        
        try {
            // ruleid: javascript-tainted-input-for-docker-api
            const output = execSync(`docker ${command}`);
            res.send(output.toString());
        } catch (error) {
            res.status(500).send(error.message);
        }
    });
}
// {/fact}

// Bad case 13: Using user input in Docker image tagging
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_13() {
    app.post('/tag-image', (req, res) => {
        const imageId = req.body.image;
        const newTag = req.body.tag;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getImage(imageId).tag({
            repo: newTag.split(':')[0],
            tag: newTag.split(':')[1] || 'latest'
        }, (err) => {
            if (err) return res.status(500).send(err);
            res.send('Image tagged successfully');
        });
    });
}
// {/fact}

// Bad case 14: Using user input in Docker container inspect
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_14() {
    app.get('/inspect-container', (req, res) => {
        const containerId = req.query.id;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).inspect((err, data) => {
            if (err) return res.status(500).send(err);
            res.json(data);
        });
    });
}
// {/fact}

// Bad case 15: Using user input in Docker container rename
// {fact rule=docker-arbitrary-container-run@v1.0 defects=1}
function bad_case_15() {
    app.put('/rename-container', (req, res) => {
        const containerId = req.body.id;
        const newName = req.body.name;
        
        // ruleid: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).rename({
            name: newName
        }, (err) => {
            if (err) return res.status(500).send(err);
            res.send('Container renamed');
        });
    });
}
// {/fact}

// True Negative Examples (Secure Code)

// Good case 1: Validating container name and image before creation
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_1() {
    app.post('/create-container', (req, res) => {
        const containerName = req.body.name;
        const imageTag = req.body.tag;
        
        // Validate container name format
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(containerName)) {
            return res.status(400).send('Invalid container name');
        }
        
        // Validate image tag against whitelist
        const allowedImages = ['node:14', 'node:16', 'node:18', 'ubuntu:20.04'];
        if (!allowedImages.includes(imageTag)) {
            return res.status(400).send('Unauthorized image');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.createContainer({
            Image: imageTag,
            name: containerName,
            Cmd: ['/bin/bash']
        }, (err, container) => {
            if (err) {
                return res.status(500).send(err);
            }
            res.send(`Container created: ${container.id}`);
        });
    });
}
// {/fact}

// Good case 2: Using a whitelist for commands in Docker exec
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_2() {
    app.get('/exec-command', (req, res) => {
        const containerId = req.query.container;
        const commandType = req.query.cmd;
        
        // Validate container ID format
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$/.test(containerId)) {
            return res.status(400).send('Invalid container ID');
        }
        
        // Use a whitelist of commands
        const allowedCommands = {
            'list': 'ls -la',
            'disk': 'df -h',
            'memory': 'free -m',
            'processes': 'ps aux'
        };
        
        if (!allowedCommands[commandType]) {
            return res.status(400).send('Command not allowed');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).exec({
            Cmd: ['sh', '-c', allowedCommands[commandType]],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) return res.status(500).send(err);
            res.send('Command executed');
        });
    });
}
// {/fact}

// Good case 3: Using sanitization for container IDs
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_3() {
    app.get('/container-logs', (req, res) => {
        let containerId = req.headers['x-container-id'];
        
        // Sanitize container ID
        containerId = containerId.replace(/[^a-f0-9]/g, '');
        
        // Additional validation
        if (containerId.length !== 12 && containerId.length !== 64) {
            return res.status(400).send('Invalid container ID format');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).logs({
            follow: true,
            stdout: true,
            stderr: true
        }, (err, stream) => {
            if (err) return res.status(500).send(err);
            stream.pipe(res);
        });
    });
}
// {/fact}

// Good case 4: Using predefined container IDs
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_4() {
    app.get('/container-stats', (req, res) => {
        const requestedContainer = req.cookies.containerName;
        
        // Map names to actual container IDs
        const containerMap = {
            'web': 'abc123def456',
            'api': 'def456abc789',
            'db': '123abc456def'
        };
        
        const containerId = containerMap[requestedContainer];
        
        if (!containerId) {
            return res.status(400).send('Unknown container');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).stats({
            stream: false
        }, (err, stats) => {
            if (err) return res.status(500).send(err);
            res.json(stats);
        });
    });
}
// {/fact}

// Good case 5: Using predefined build contexts
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_5() {
    app.post('/build-image', (req, res) => {
        const projectId = req.body.project;
        const version = req.body.version;
        
        // Validate project ID
        if (!/^[a-zA-Z0-9-]+$/.test(projectId)) {
            return res.status(400).send('Invalid project ID');
        }
        
        // Validate version
        if (!/^\d+\.\d+\.\d+$/.test(version)) {
            return res.status(400).send('Invalid version format');
        }
        
        const tag = `${projectId}:${version}`;
        const dockerfilePath = `/opt/build-contexts/${projectId}`;
        
        // ok: javascript-tainted-input-for-docker-api
        docker.buildImage({
            context: dockerfilePath,
            src: ['Dockerfile']
        }, {
            t: tag
        }, (err, stream) => {
            if (err) return res.status(500).send(err);
            res.send('Building image...');
        });
    });
}
// {/fact}

// Good case 6: Using sanitization for volume names
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_6() {
    app.get('/create-volume/:name', (req, res) => {
        let volumeName = req.params.name;
        
        // Sanitize volume name
        volumeName = volumeName.replace(/[^a-zA-Z0-9_.-]/g, '');
        
        if (volumeName.length < 1 || volumeName.length > 32) {
            return res.status(400).send('Invalid volume name length');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.createVolume({
            Name: volumeName,
            Driver: 'local'
        }, (err, volume) => {
            if (err) return res.status(500).send(err);
            res.json(volume);
        });
    });
}
// {/fact}

// Good case 7: Using whitelist for network drivers
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_7() {
    app.post('/create-network', (req, res) => {
        const networkName = req.body.name;
        const requestedDriver = req.body.driver;
        
        // Validate network name
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(networkName)) {
            return res.status(400).send('Invalid network name');
        }
        
        // Whitelist of allowed drivers
        const allowedDrivers = ['bridge', 'overlay', 'macvlan'];
        const driver = allowedDrivers.includes(requestedDriver) ? requestedDriver : 'bridge';
        
        // ok: javascript-tainted-input-for-docker-api
        docker.createNetwork({
            Name: networkName,
            Driver: driver
        }, (err, network) => {
            if (err) return res.status(500).send(err);
            res.json(network);
        });
    });
}
// {/fact}

// Good case 8: Using whitelist for images and commands
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_8() {
    app.get('/run-container', (req, res) => {
        const requestedImage = req.query.image;
        const requestedCmd = req.query.cmd;
        
        // Whitelist of allowed images
        const allowedImages = ['alpine:latest', 'busybox:latest', 'ubuntu:20.04'];
        if (!allowedImages.includes(requestedImage)) {
            return res.status(400).send('Unauthorized image');
        }
        
        // Whitelist of allowed commands
        const allowedCommands = {
            'date': 'date',
            'hostname': 'hostname',
            'network': 'ifconfig'
        };
        
        if (!allowedCommands[requestedCmd]) {
            return res.status(400).send('Command not allowed');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.run(requestedImage, ['sh', '-c', allowedCommands[requestedCmd]], process.stdout, (err, data) => {
            if (err) return res.status(500).send(err);
            res.send(`Container exited with code ${data.StatusCode}`);
        });
    });
}
// {/fact}

// Good case 9: Using validation for container removal
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_9() {
    app.delete('/remove-container', (req, res) => {
        const containerId = req.body.id;
        
        // Validate container ID
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$/.test(containerId)) {
            return res.status(400).send('Invalid container ID');
        }
        
        // Check if container exists and is not protected
        docker.getContainer(containerId).inspect((err, data) => {
            if (err) return res.status(404).send('Container not found');
            
            // Check for protected label
            if (data.Config.Labels && data.Config.Labels.protected === 'true') {
                return res.status(403).send('Cannot remove protected container');
            }
            
            // ok: javascript-tainted-input-for-docker-api
            docker.getContainer(containerId).remove({
                force: false
            }, (err) => {
                if (err) return res.status(500).send(err);
                res.send('Container removed');
            });
        });
    });
}
// {/fact}

// Good case 10: Using whitelist for image pulls
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_10() {
    app.post('/pull-image', (req, res) => {
        const requestedImage = req.body.image;
        
        // Whitelist of allowed images
        const allowedImages = [
            'node:14', 'node:16', 'node:18',
            'python:3.8', 'python:3.9', 'python:3.10',
            'nginx:latest', 'redis:latest'
        ];
        
        if (!allowedImages.includes(requestedImage)) {
            return res.status(400).send('Unauthorized image');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.pull(requestedImage, (err, stream) => {
            if (err) return res.status(500).send(err);
            docker.modem.followProgress(stream, (err, output) => {
                if (err) return res.status(500).send(err);
                res.send('Image pulled successfully');
            });
        });
    });
}
// {/fact}

// Good case 11: Using predefined shell commands
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_11() {
    app.post('/exec-shell', (req, res) => {
        const containerId = req.body.container;
        const commandKey = req.body.command;
        
        // Validate container ID
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$/.test(containerId)) {
            return res.status(400).send('Invalid container ID');
        }
        
        // Predefined commands
        const commands = {
            'update': 'apt-get update',
            'disk': 'df -h',
            'network': 'netstat -tuln',
            'processes': 'ps aux'
        };
        
        if (!commands[commandKey]) {
            return res.status(400).send('Unknown command');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).exec({
            Cmd: ['/bin/sh', '-c', commands[commandKey]],
            AttachStdout: true,
            AttachStderr: true
        }, (err, exec) => {
            if (err) return res.status(500).send(err);
            exec.start({}, (err, stream) => {
                if (err) return res.status(500).send(err);
                res.send('Command executed');
            });
        });
    });
}
// {/fact}

// Good case 12: Using predefined Docker CLI commands
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_12() {
    app.post('/docker-cli', (req, res) => {
        const commandType = req.body.type;
        
        // Predefined commands
        const commands = {
            'ps': 'docker ps',
            'images': 'docker images',
            'version': 'docker version',
            'info': 'docker info'
        };
        
        if (!commands[commandType]) {
            return res.status(400).send('Unknown command type');
        }
        
        try {
            // ok: javascript-tainted-input-for-docker-api
            const output = execSync(commands[commandType]);
            res.send(output.toString());
        } catch (error) {
            res.status(500).send(error.message);
        }
    });
}
// {/fact}

// Good case 13: Using validation for image tagging
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_13() {
    app.post('/tag-image', (req, res) => {
        const imageId = req.body.image;
        const newRepo = req.body.repo;
        const newTag = req.body.tag || 'latest';
        
        // Validate image ID
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$|^[a-zA-Z0-9]+:[a-zA-Z0-9.]+$/.test(imageId)) {
            return res.status(400).send('Invalid image ID or name');
        }
        
        // Validate repository name
        if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/.test(newRepo)) {
            return res.status(400).send('Invalid repository name');
        }
        
        // Validate tag
        if (!/^[a-zA-Z0-9_.-]+$/.test(newTag)) {
            return res.status(400).send('Invalid tag');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getImage(imageId).tag({
            repo: newRepo,
            tag: newTag
        }, (err) => {
            if (err) return res.status(500).send(err);
            res.send('Image tagged successfully');
        });
    });
}
// {/fact}

// Good case 14: Using container ID validation for inspect
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_14() {
    app.get('/inspect-container', (req, res) => {
        const containerId = req.query.id;
        
        // Validate container ID format
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$/.test(containerId)) {
            return res.status(400).send('Invalid container ID format');
        }
        
        // Additional authorization check
        const userRole = getUserRole(req); // Assume this function exists
        if (userRole !== 'admin' && userRole !== 'operator') {
            return res.status(403).send('Insufficient permissions');
        }
        
        // ok: javascript-tainted-input-for-docker-api
        docker.getContainer(containerId).inspect((err, data) => {
            if (err) return res.status(500).send(err);
            res.json(data);
        });
    });
}
// {/fact}

// Good case 15: Using validation for container rename
// {fact rule=docker-arbitrary-container-run@v1.0 defects=0}
function good_case_15() {
    app.put('/rename-container', (req, res) => {
        const containerId = req.body.id;
        const newName = req.body.name;
        
        // Validate container ID
        if (!/^[a-f0-9]{12}$|^[a-f0-9]{64}$/.test(containerId)) {
            return res.status(400).send('Invalid container ID');
        }
        
        // Validate new name
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(newName) || newName.length > 32) {
            return res.status(400).send('Invalid container name');
        }
        
        // Check if container exists
        docker.getContainer(containerId).inspect((err, data) => {
            if (err) return res.status(404).send('Container not found');
            
            // ok: javascript-tainted-input-for-docker-api
            docker.getContainer(containerId).rename({
                name: newName
            }, (err) => {
                if (err) return res.status(500).send(err);
                res.send('Container renamed');
            });
        });
    });
}
// {/fact}

// Helper function for good_case_14
function getUserRole(req) {
    // In a real application, this would check user authentication
    // For this example, we'll return a fixed role
    return 'admin';
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});