import ActionButton from 'action-button'
import ActionToggle from 'action-toggle'
import GenericInput from 'json-schema-input'
import Icon from 'icon'
import React, { Component } from 'react'
import _ from 'messages'
import map from 'lodash/map'
import { addSubscriptions } from 'utils'
import { lastly } from 'promise-toolbox'
import {
  configurePlugin,
  disablePluginAutoload,
  enablePluginAutoload,
  loadPlugin,
  purgePluginConfiguration,
  subscribePlugins,
  unloadPlugin
} from 'xo'

class Plugin extends Component {
  constructor (props) {
    super(props)

    // Don't update input with schema in edit mode!
    // It's always the same!
    this.state = {
      configurationSchema: props.configurationSchema
    }
    this.formId = `form-${props.id}`
  }

  componentWillReceiveProps (nextProps) {
    // Don't update input with schema in edit mode!
    if (!this.state.edit) {
      this.setState({
        configurationSchema: nextProps.configurationSchema
      })

      if (this.refs.pluginInput) {
        // TODO: Compare values!!!
        this.refs.pluginInput.value = nextProps.configuration
      }
    }
  }

  _updateExpanded = () => {
    this.setState({
      expanded: !this.state.expanded
    })
  }

  _setAutoload = (event) => {
    if (this._updateAutoload) {
      return
    }

    this._updateAutoload = true

    const method = event.target.checked ? enablePluginAutoload : disablePluginAutoload

    method(this.props.id)::lastly(() => {
      this._updateAutoload = false
    })
  }

  _updateLoad = () => {
    const { props } = this
    const { id } = props

    const method = (!props.loaded && loadPlugin) || (!props.unloadable && unloadPlugin)

    if (method) {
      return method(id)
    }
  }

  _saveConfiguration = async () => {
    try {
      await configurePlugin(this.props.id, this.refs.pluginInput.value)

      this.setState({
        edit: false
      })
    } catch (_) { }
  }

  _deleteConfiguration = async () => {
    try {
      await purgePluginConfiguration(this.props.id)
      this.refs.pluginInput.value = undefined
    } catch (_) { }
  }

  _edit = () => {
    this.setState({
      edit: true
    })
  }

  _cancelEdit = () => {
    this.setState({
      edit: false
    })
  }

  render () {
    const {
      props,
      state
    } = this
    const { expanded, edit } = state
    const { loaded } = props
    const { formId } = this

    return (
      <div className='card-block'>
        <h4 className='form-inline clearfix'>
          <ActionToggle disabled={loaded && props.unloadable} value={loaded} handler={this._updateLoad} />
          <span className='text-primary'>
            {` ${props.name} `}
          </span>
          <span>
            {`(v${props.version}) `}
          </span>
          <div className='checkbox small'>
            <label className='text-muted'>
              {_('autoloadPlugin')} <input type='checkbox' checked={props.autoload} onChange={this._setAutoload} />
            </label>
          </div>
          <div className='form-group pull-right small'>
            <button type='button' className='btn btn-primary' onClick={this._updateExpanded}>
              <Icon icon={expanded ? 'minus' : 'plus'} />
            </button>
          </div>
        </h4>
        {expanded &&
          <form id={formId}>
            <GenericInput
              disabled={!edit}
              label='Configuration'
              schema={state.configurationSchema}
              required
              ref='pluginInput'
              defaultValue={props.configuration}
            />
            <div className='form-group pull-xs-right'>
              <div className='btn-toolbar'>
                <div className='btn-group'>
                  <ActionButton disabled={!edit} type='submit' form={formId} icon='save' className='btn-primary' handler={this._saveConfiguration}>
                    {_('savePluginConfiguration')}
                  </ActionButton>
                </div>
                <div className='btn-group'>
                  <ActionButton disabled={!edit} icon='delete' className='btn-danger' handler={this._deleteConfiguration}>
                    {_('deletePluginConfiguration')}
                  </ActionButton>
                </div>
                {!edit ? (
                  <div className='btn-group'>
                    <button type='button' className='btn btn-primary' onClick={this._edit}>
                      {_('editPluginConfiguration')}
                    </button>
                  </div>
                ) : (
                  <div className='btn-group'>
                    <button type='button' className='btn btn-primary' onClick={this._cancelEdit}>
                      {_('cancelPluginEdition')}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </form>
        }
      </div>
    )
  }
}

@addSubscriptions({
  plugins: subscribePlugins
})
export default class Plugins extends Component {
  render () {
    return (
      <div>
        <h2>
          <Icon icon='menu-settings-plugins' />
          <span>Plugins</span>
        </h2>
        <ul style={{'paddingLeft': 0}} >
          {map(this.props.plugins, (plugin, key) =>
            <li key={key} className='list-group-item clearfix'>
              <Plugin {...plugin} />
            </li>
          )}
        </ul>
      </div>
    )
  }
}
