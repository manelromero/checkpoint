# Add
@app.route('/add/<className>/<action>', methods=['GET', 'POST'])
@login_required
def add(className, action):
    form = instantiateForm(className, request.form)
    object = instantiateObject(className)
    if request.method == 'POST' and form.validate():
        data = {}
        for element in form:
            data[element.short_name.replace('_', '-')] = element.data
        call = apiCall(action, data, session['sid'])
        flash('Element afegit!')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[3:]+'s',
            className=className
            ))
    else:
        return render_template(
            'new.html',
            action=action,
            className=className,
            form=form
            )


# Show
@app.route('/show/<className>/<action>')
@login_required
def show(className, action):
    objects = []
    call = apiCall(action, {}, session['sid'])
    for element in call['objects']:
        data = {'uid': element['uid']}
        call = apiCall(action[:-1], data, session['sid'])
        object = instantiateObject(className)
        for attr, value in object.__dict__.items():
            setattr(object, attr, call[attr.replace('_', '-')])
        objects.append(object)
    return render_template(
        'show.html',
        objects=objects,
        action=action,
        className=className,
        sample=call
        )


# Edit
@app.route('/edit/<className>/<action>/<object_uid>', methods=['GET', 'POST'])
@login_required
def edit(className, action, object_uid):
    form = instantiateForm(className, request.form)
    object = instantiateObject(className)
    data = {'uid': object_uid}
    call = apiCall('show'+action[3:], data, session['sid'])
    for attr, value in object.__dict__.items():
        setattr(object, attr, call[attr.replace('_', '-')])
    if request.method == 'POST' and form.validate():
        data = {}
        for element in form:
            data[element.short_name.replace('_', '-')] = element.data
        call = apiCall(action, data, session['sid'])
        flash('Element afegit!')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[3:]+'s',
            className=className
            ))
    else:
        return render_template(
            'edit.html',
            object=object,
            action=action,
            className=className,
            form=form
            )


# Delete
@app.route(
    '/delete/<className>/<action>/<object_uid>',
    methods=['GET', 'POST']
    )
@login_required
def delete(className, action, object_uid):
    data = {'uid': object_uid}
    call = apiCall('show'+action[6:], data, session['sid'])
    object = instantiateObject(className)
    for attr, value in object.__dict__.items():
        setattr(object, attr, call[attr.replace('_', '-')])
    if request.method == 'POST':
        call = apiCall(action, data, session['sid'])
        flash('Element esborrat')
        session['changes'] += 1
        return redirect(url_for(
            'show',
            action='show'+action[6:]+'s',
            className=className
            ))
    else:
        return render_template(
            'delete.html',
            object=object,
            action=action,
            className=className
            )
