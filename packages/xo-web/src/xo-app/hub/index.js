import _ from 'intl'
import decorate from 'apply-decorators'
import Icon from 'icon'
import Page from '../page'
import React from 'react'
import { Container, Col, Row } from 'grid'
import { addSubscriptions } from 'utils'
import { subscribePlugins, subscribeResourceCatalog } from 'xo'
import { filter, map, mapValues, orderBy } from 'lodash'
import { injectState, provideState } from 'reaclette'
import { DropdownButton, MenuItem } from 'react-bootstrap-4/lib'

import example from './example'
import Resource from './resource'
import './style.css'

// ==================================================================

const SORT_OPTIONS = [
  {
    labelId: 'catalogSortByPopularity',
    sortBy: 'popularity',
    sortOrder: 'desc',
  },
  {
    labelId: 'catalogSortByName',
    sortBy: 'name',
    sortOrder: 'asc',
  },
]

const HEADER = (
  <Container>
    <h2>
      <Icon icon='menu-hub' /> {_('hubPage')}
    </h2>
  </Container>
)

export default decorate([
  addSubscriptions({
    catalog: subscribeResourceCatalog,
    plugins: subscribePlugins,
  }),
  provideState({
    initialState: () => ({
      sortBy: undefined,
      sortOrder: undefined,
    }),
    effects: {
      setSort(
        _,
        {
          currentTarget: {
            dataset: { sortBy, sortOrder },
          },
        }
      ) {
        return { sortBy, sortOrder }
      },
    },
    computed: {
      resources: ({ availableResources, sortBy, sortOrder }) =>
        orderBy(availableResources, res => res[sortBy], sortOrder),
      availableResources: (_, { catalog }) => {
        catalog = example
        return mapValues(
          filter(catalog, (_, res) => !res.startsWith('_')),
          'xva'
        )
      },
      sortTitle: ({ sortBy }) =>
        sortBy === undefined ? _('homeSortBy') : sortBy,
    },
  }),
  injectState,
  ({ effects, state: { resources, sortTitle } }) => (
    <Page
      header={HEADER}
      title='hubPage'
      formatTitle
      className='background-page'
    >
      <Row>
        <Col>
          <span className='pull-right'>
            <DropdownButton bsStyle='link' id='sort' title={sortTitle}>
              {map(SORT_OPTIONS, ({ labelId, sortBy, sortOrder }, key) => (
                <MenuItem
                  data-sort-by={sortBy}
                  data-sort-order={sortOrder}
                  key={key}
                  onClick={effects.setSort}
                >
                  {_(labelId)}
                </MenuItem>
              ))}
            </DropdownButton>
          </span>
        </Col>
      </Row>
      <br />
      <Row>
        {map(resources, ({ name, popularity, size, version }, key) => (
          <Col key={key} mediumSize={3}>
            <Resource
              className='card-style'
              name={name}
              popularity={popularity}
              size={size}
              version={version}
            />
          </Col>
        ))}
      </Row>
    </Page>
  ),
])
