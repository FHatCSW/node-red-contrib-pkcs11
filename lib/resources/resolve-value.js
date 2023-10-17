function resolveValue(message_object, context, global_context, flow_context, value) {

    let result;
    if (context === 'msg') {
        const propertyNames = value.split('.');
        let target = message_object;
        for (const propName of propertyNames) {
            if (target && target.hasOwnProperty(propName)) {
                target = target[propName];
            } else {
                // Property doesn't exist, handle this case as needed
                console.log(`Property "${propName}" does not exist.`);
                return undefined; // or handle an error, return a default value, etc.
            }
        }
        result = target;
    } else if (context === 'global') {
        result = global_context.get(value);
    } else if (context === 'flow') {
        result = flow_context.get(value);
    } else if (context === 'str') {
        result = value;
    }

    // Check if certificate is still undefined
    if (result === undefined) {
        throw new Error(value + ' can not be found. Please check your input value');
    }

    return result;
}

module.exports = resolveValue;